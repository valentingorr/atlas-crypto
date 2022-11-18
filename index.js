const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const parseSalt = salt => [...salt.split(""), ...(new Array(32).fill("0"))].slice(0, 32).join("");

module.exports = (p = {}) => {
    const parameters = {
        iv: new Buffer.from(new Array(16).fill(552), "hex"),
        salts: {},
        ...p,
    };
    if(Buffer.byteLength(parameters.iv) !== 16) throw new Error("Iv byteLength must be 16");
    const algorithm = "aes-256-ctr";
    const encrypt = (data, salt) => {
        const cipher = crypto.createCipheriv(algorithm, salt, parameters.iv);
        const encrypted = Buffer.concat([ cipher.update(data), cipher.final() ]);
        return encrypted.toString("hex");
    };
    
    const decrypt = (hash, salt) => {
        const decipher = crypto.createDecipheriv(algorithm, salt, parameters.iv);
        const decrypted = Buffer.concat([ decipher.update(Buffer.from(hash, "hex")), decipher.final() ]);
        return decrypted.toString();
    };
    
    return (db) => {

        const unCryptTable = table => {
            db.appendLog(`unCrypting -> ${table.name}`, ">");
            const startTime = new Date().getTime();
            const cKeys = Object.keys(table.schema.items).map(item => {
                return table.schema.items[item].hasOwnProperty("crypto") ? {
                    item, salt: table.schema.items[item].crypto
                } : false;
            }).filter(key => key !== false);
            db.table(table.name).map(item => {
                const uC = {};
                cKeys.forEach(key => {
                    const salt = parameters.salts[key.salt];
                    if(!salt) return;
                    uC[key.item] = decrypt(item[key.item], parseSalt(salt));
                });
                return {
                    ...item,
                    ...uC
                }
            });
            db.appendLog(`unCrypted -> ${table.name} (${new Date().getTime() - startTime}ms)`, ">");
        };

        return {
            name: require("./package.json").name,
            proxy: (event, original, amended) => {
                const dispatcher = JSON.parse(fs.readFileSync(db.dbParameters.path, "utf-8"));
                const items = dispatcher.tables.find(table => table.name === event.table).schema.items;
                const cItems = new Array();
                Object.keys(items).forEach(key => {
                    if(!(items[key].hasOwnProperty("crypto")) || items[key].crypto === "") return;
                    const salt = parameters.salts[items[key].crypto];
                    if(!salt) throw new Error("invalid salt");
                    return cItems.push({ key, salt: parseSalt(salt)  });
                });
                switch(event.method) {
                    case "insert":
                        cItems.forEach(cItem => {
                            amended.hasOwnProperty(cItem.key) ? amended[cItem.key] = encrypt(amended[cItem.key], cItem.salt) : null
                        });
                        return amended;
                        break;
                    case "select":
                        return amended.map(item => {
                            cItems.forEach(cItem => {
                                item.hasOwnProperty(cItem.key) ? item[cItem.key] = decrypt(item[cItem.key], cItem.salt) : null
                            });
                            return item;
                        });
                        break;
                }
                return amended;
            },
            init: () => {
                db.customMethods["unCryptTable"] = (tableName) => unCryptTable(db.dispatcher.tables.find(t => t.name === tableName));
                db.customTableMethods["unCrypt"] = table => unCryptTable(db.dispatcher.tables.find(t => t.name === table.tableName));
            },
            unuse: () => {
                db.dispatcher.tables.forEach(table => unCryptTable(table));
            }
        }
    };
};