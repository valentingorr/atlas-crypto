# Atlas Crypto

```sh
$ npm install atlas-crypto json-atlas
```

```js
db.table("items").schema = {
    alias: "item",
    items: {
        token: {
            type: "string",
            crypto: "saltname1" // set the salt id
        }
    }
};

const atlasCrypto = require("atlas-crypto");
db.use(atlasCrypto({
    iv: new Buffer.from(new Array(16).fill(552), "hex"), // set init vector for encryption (optional, but recommanded to set a custom one)
    salts: {
        "saltname1": "yourKey", // encryption / description key (max 32 characters)
        "saltname2": "yourSndKey"
    }
}));
```