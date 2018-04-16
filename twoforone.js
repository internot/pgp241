try {
    var openpgp = require('openpgp');
} catch(e){}

openpgp.config.ignore_mdc_error = true;

var twoforone = function() {
    
    var zero = new Uint8Array(16), // Zero vector
        E = new openpgp.crypto.cipher.aes256(new Uint8Array(32)), // Encryption function
        c0; // Randomly chosen first block of cipher text
    
    function genAsymKeys() {
        openpgp.generateKey({
            userIds: [{ name:'Jonas', email:'jonas@assured.se' }]
        }).then(function(key) {
            document.getElementById("pubkey1").value = key.publicKeyArmored;
            document.getElementById("privkey1").value = key.privateKeyArmored;
        });
        openpgp.generateKey({
            userIds: [{ name:'internot', email:'jonas@cure53.de' }]
        }).then(function(key) {
            document.getElementById("pubkey2").value = key.publicKeyArmored;
            document.getElementById("privkey2").value = key.privateKeyArmored;
        });
    }
    
    function findKeys(extended) {
        
        var time = new Date(),
            o0, // 0th output block
            o1, // 1st output block
            h = {}; // Candidates
            
        E.key = new Uint8Array(32);
    
        console.log("Generate keys until a matching pair has been found");

        for (var i = 0; i < Math.pow(2,25); i++) {
            
            var n = 0,
                n_ = 0;
            
            initKey(E.key, i);

            // This is the proper way to do it. It can be optimised.

            o0 = E.encrypt(zero);
            o1 = E.encrypt(c0.subarray(0, 16));
            
            c0[16] = c0[14] ^ o0[14] ^ o1[0];
            c0[17] = c0[15] ^ o0[15] ^ o1[1];
            
            // Resync step
            o1 = E.encrypt(c0.subarray(2));
            
            n = (c0[16]<<24) | (c0[17]<<16) | (o1[0]<<8) | o1[1];
            n_ = (c0[16]<<24) | (c0[17]<<16) | ((o1[0]^1)<<8) | o1[1];

            // This handles when messages have two vs three octet lengths 
            if (extended[0]) {
                n = n * 256 + o1[2];
                n_ = n_ * 256 + (o1[2] ^ 7);
            } else {
                n_ ^= extended[1] ? 5 : 2;
            }
            h[n] = i;
            
            if (h[n_] !== undefined) {
            
                console.log('Sooouuper JACKPOT!\n' +
                            'K0: ' + h[n_] + '\n' +
                            'K1: ' + i + '\n' +
                            'Stats: ' + i + ' iterations in ' + (new Date() - time) + ' ms');
                
                return [
                    initKey(new Uint8Array(32), h[n_]), 
                    initKey(new Uint8Array(32), i)
                ];
            }
        }
    }
    
    function initKey(k, i) {
        
        var j = 0;
        while (i >>> j*8 > 0) {
            k[j] = i >>> j++ * 8 & 0xff;
        }
        return k;
    }
    
    function initIV(k) {
        var E = new openpgp.crypto.cipher.aes256(k);
        var iv = E.encrypt(zero);
        for (var i = 0; i < 16; i++) {
            iv[i] ^= c0[i];
        }
        return iv;
    }
    
    function writeHeader(type, length) {
        
        if (length < 192)
            return new Uint8Array([0xc0 | type, length]);
        else
            return new Uint8Array([0xc0 | type, ((length - 192) >> 8) + 192, (length - 192) & 0xFF]);
    }

    async function encrypt() {
        
        var pubkey = [
                openpgp.key.readArmored(document.getElementById("pubkey1").value).keys[0],
                openpgp.key.readArmored(document.getElementById("pubkey2").value).keys[0]
            ],
            message = [
                document.getElementById("message1").value,
                document.getElementById("message2").value
            ];
            
        // Shortest length first
        if (message[0].length > message[1].length) {
            message = [message[1], message[0]];
            pubkey = [pubkey[1], pubkey[0]];
        }
        
        // 2 + 1 + 1 + pad + 4 + message[0].length + 2 == full block
        var extended = [];
        extended[1] =     1 + 1 + 6 + 4 + message[1].length > 191;
        extended[0] = 2 + 1 + 1 + 1 + 4 + message[0].length + 2 + extended[1] > 192;

        // We don't need to generate a new C0, we could just use a known collision
        c0 = await openpgp.crypto.random.getRandomBytes(18);
        
        var K = findKeys(extended);
        
        console.log("Prepare first message");
        
        // [tag,length,'u',length,'msg.txt',date,msg]

        var pad = 16 - (10 + extended[0] + extended[1] + message[0].length) % 16,
            length = [
                message[0].length + 6 + pad,
                message[1].length + 6 + 6
            ];

        var literal = new openpgp.packet.Literal();
        literal.setText(message[0]);
        literal.setFilename('easter.egg.hunt.'.substr(0, pad));
        
        message[0] = openpgp.util.concatUint8Array([
            writeHeader(openpgp.enums.packet.literal, length[0]), 
            literal.write(),
            writeHeader(openpgp.enums.packet.marker, length[1] + 2 + extended[1])
        ]);
        
        console.log("Encrypt first message");
        
        var encrypted = openpgp.crypto.cfb.encrypt( initIV(K[0]), 'aes256', message[0], K[0], true );
        
        console.log("Prepare second message");
        
        literal.setText(message[1]);
        literal.setFilename('PGP241');
        message[1] = openpgp.util.concatUint8Array([
            writeHeader(openpgp.enums.packet.literal, length[1]), 
            literal.write()
        ]);
        
        console.log("Encrypt second message");
    
        encrypted = openpgp.util.concatUint8Array([
            encrypted,
            openpgp.crypto.cfb.normalEncrypt( 'aes256', K[1], message[1], encrypted.subarray(-16))
        ]);
        
        var list = new openpgp.packet.List();
        
        var se = new openpgp.packet.SymmetricallyEncrypted();
        se.encrypted = encrypted;
        list.push(se);
        
        console.log("Encrypt symmetric keys");
        
        list.concat((await openpgp.message.encryptSessionKey(K[0], 'aes256', [pubkey[0]])).packets);
        list.concat((await openpgp.message.encryptSessionKey(K[1], 'aes256', [pubkey[1]])).packets);
        
        console.log("Armor PGP message");
        
        document.getElementById("pgpmessage").value = (new openpgp.message.Message(list)).armor();
        
    }
    
    async function decrypt(){
        console.log("Decrypting message");
        
        var privkey1 = document.getElementById("privkey1").value,
            privkey2 = document.getElementById("privkey2").value,
            pgpmessage = document.getElementById("pgpmessage").value;
        
        if (pgpmessage.length > 0) {
            
            console.log("Decrypting first message");
            document.getElementById("decrypted1").value = (await openpgp.decrypt({
                message: openpgp.message.readArmored(pgpmessage),
                privateKeys: openpgp.key.readArmored(privkey1).keys
            })).data;
            
            console.log("Decrypting second message");
            document.getElementById("decrypted2").value = (await openpgp.decrypt({
                message: openpgp.message.readArmored(pgpmessage),
                privateKeys: openpgp.key.readArmored(privkey2).keys
            })).data;
        }
    }
    
    return {
        'genAsymKeys': genAsymKeys,
        'genSymKeys': findKeys,
        'encrypt': encrypt,
        'decrypt': decrypt
    };
}();

document.getElementById("genasymkey").addEventListener("click", twoforone.genAsymKeys);

document.getElementById("encrypt").addEventListener("click", twoforone.encrypt);

document.getElementById("decrypt").addEventListener("click", twoforone.decrypt);