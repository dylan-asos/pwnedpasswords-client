function PwnedPasswords(options = {}) {

    let defaults = {
        breachThreshold: 100,
        passwordsApiBaseUri: "https://api.pwnedpasswords.com/range/"
    };

    let settings = Object.assign({}, defaults, options);

    var hashInput = function(string) {
        
        const buffer = new TextEncoder("utf-8").encode(string);

        return window.crypto.subtle.digest("SHA-1", buffer).then(function(bufferData) {
            const hexCodes = [];
            const view = new DataView(bufferData);
            for (let i = 0; i < view.byteLength; i += 4) {
                const value = view.getUint32(i);
                const stringValue = value.toString(16);
                const padding = "00000000";
                const paddedValue = (padding + stringValue).slice(-padding.length);
                hexCodes.push(paddedValue);
            }
            return hexCodes.join("");
        });

    };

    var callApi = function(hash) {
        return new Promise(function(resolve, reject) {
            const req = new XMLHttpRequest();

            req.addEventListener("load",
                function() {
                    const result = {
                        hashed: hash,
                        responseText: req.responseText
                    };

                    resolve(result);
                });

            req.open('GET', settings.passwordsApiBaseUri + hash.substr(0, 5));
            req.send();
        });
    };

    var produceCandidateList = function(apiData) {
        return new Promise(function(resolve, reject) {
            const items = apiData.responseText.split("\n");
            const hashSub = apiData.hashed.slice(5).toUpperCase();
            const result = {
                items: items,
                hash: hashSub
            };
            resolve(result);
        });
    };

    var parseResult = function(result) {
        return new Promise(function(resolve, reject) {
            const pwnedResult = {
                breached: false,
                count: 0
            };

            for (let index = 0; index < result.items.length; index++) {
                if (result.items[index].substring(0, 35) === result.hash) {
                    const breachCount = result.items[index].split(":")[1];
                    pwnedResult.count = breachCount;
                    if (parseInt(breachCount) > parseInt(settings.breachThreshold)) {
                        pwnedResult.breached = true;
                    }
                    break;
                }
            }

            resolve(pwnedResult);
        });
    };

    return {
        checkStrength: function(input) {
            return hashInput(input)
                .then(callApi)
                .then(produceCandidateList)
                .then(parseResult);
        }
    };
}