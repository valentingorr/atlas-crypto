const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

module.exports = (p = {}) => {
    const parameters = {
        iv: new Buffer.from(new Array(16).fill(5), "hex"),
        ...p
    };
    if(!(parameters.hasOwnProperty("salt"))) throw new Error("You must provide the salt.");
    const algorithm = "aes-256-ctr";
    const encrypt = data => {
        const cipher = crypto.createCipheriv(algorithm, parameters.salt, parameters.iv);
        const encrypted = Buffer.concat([ cipher.update(data), cipher.final() ]);
        return encrypted.toString("hex");
    };
    
    const decrypt = hash => {
        const decipher = crypto.createDecipheriv(algorithm, parameters.salt, parameters.iv);
        const decrypted = Buffer.concat([ decipher.update(Buffer.from(hash, "hex")), decipher.final() ]);
        return decrypted.toString();
    };
    return (db) => {
        return {
            proxy: (event, original, amended) => {
                const dispatcher = JSON.parse(fs.readFileSync(db.dbParameters.path, "utf-8"));
                const items = dispatcher.tables.find(table => table.name === event.table).schema.items;
                const cItems = new Array();
                Object.keys(items).forEach(key => items[key].hasOwnProperty("crypto") && items[key].crypto ? cItems.push(key) : null );
                switch(event.method) {
                    case "insert":
                        cItems.forEach(key => {
                            if(amended.hasOwnProperty(key)) amended[key] = encrypt(amended[key]);
                        });
                        return amended;
                        break;
                    case "select":
                        return amended.map(item => {
                            return {
                                ...item
                            }
                        });
                        break;
                }
                return amended;
            }
        }
    };
};
