try {
    var openpgp = require('openpgp');
} catch(e){}

openpgp.config.ignore_mdc_error = true;

var twoforone = function() {

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
    
    async function findKeys() {
        console.log("Making secret sauce");
        
        var time = new Date(),
            zero = new Uint8Array(16), // Zero vector
            E = new openpgp.crypto.cipher.aes256(zero), // Encryption function
            K, // Random key
            o0, // 0th output block
            o1, // 1st output block
            c0 = new Uint8Array(18), // Randomly chosen first block of cipher text
            h = {}, // Candidates
            m; // Match!
    
        try {
            
            console.log("Randomly choose first cipher block");
            // Optimization that reduces the number of AES operations
            // c0 = zero.slice(0); // await openpgp.crypto.random.getRandomBytes(16);
            
            console.log("Generate keys until a matching pair has been found");
    
            for (var i = 0; i < Math.pow(2,16); i++) {
                K = E.key = await openpgp.crypto.random.getRandomBytes(32);
                o0 = E.encrypt(zero);
                o1 = o0;// (new openpgp.crypto.cipher.aes256(K)).encrypt(c0);
                
                c0[16] = o0[14]^o1[0]; // c0[14]^o0[14]^o1[0];
                c0[17] = o0[15]^o1[1]; // c0[15]^o0[15]^o1[1];
                
                // Resynch step
                o1 = E.encrypt(c0.subarray(2));
                
                // The following line is hideous! :)
                (((h[c0[16]] = {...h[c0[16]]})
                    [c0[17]] = {...h[c0[16]][c0[17]]})
                    [o1[0]] = {...h[c0[16]][c0[17]][o1[0]]})
                    [o1[1]] = {'K': K, 'o0': o0, 'o1': o1};
                
                for (var n in h[c0[16]][c0[17]][o1[0]^11^10]) {
    
                    if (((n ^ o1[1]) & 0xc0) == 0x80) {
                        m = h[c0[16]][c0[17]][o1[0]^11^10][n];
                        console.log('Sooouuper JACKPOT!\n' +
                                    'K0: ' + openpgp.util.Uint8Array_to_hex(m.K) + '\n' +
                                    'o:  ' + [m.o0[14], m.o0[15], m.o0[0], m.o0[1], m.o1[0], m.o1[1]] + '\n' +
                                    'p:  ' + [c0[14] ^ m.o0[14], c0[15] ^ m.o0[15], c0[16] ^ m.o0[0], c0[17] ^ m.o0[1], o1[0] ^ m.o1[0], o1[1] ^ m.o1[1]] + '\n' +
                                    'c:  ' + [c0[14], c0[15], c0[16], c0[17], o1[0], o1[1]] + '\n' +
                                    'K1: ' + openpgp.util.Uint8Array_to_hex(K) + '\n' +
                                    'o\': ' + [o0[14], o0[15], o0[0], o0[1], o1[0], o1[1]] + '\n' +
                                    'p\': ' + [c0[14] ^ o0[14], c0[15] ^ o0[15], c0[16] ^ o0[0], c0[17] ^ o0[1], 0, 0] + '\n' + 
                                    'c\': ' + [c0[14], c0[15], c0[16], c0[17], o1[0], o1[1]] + '\n' +
                                    'Stats: ' + i + ' iterations in ' + (new Date() - time) + ' ms');
                        
                        document.getElementById("symkey1").value = openpgp.util.Uint8Array_to_hex(m.K);
                        document.getElementById("symkey2").value = openpgp.util.Uint8Array_to_hex(K);
                        document.getElementById("iv1").value = openpgp.util.Uint8Array_to_hex(m.o0); // m.o0.map((x,i)=>x^c0[i]));
                        document.getElementById("iv2").value = openpgp.util.Uint8Array_to_hex(o0); // o0.map((x,i)=>x^c0[i]));
                        
                        return [m, h[c0[16]][c0[17]][o1[0]][o1[1]]];
                    }
                }
            }
        } catch(e) {
            console.log(e);
        }
    }

    async function encrypt() {
        console.log('Making more secret sauce');
        
        var pubkey1 = openpgp.key.readArmored(document.getElementById("pubkey1").value).keys[0],
            pubkey2 = openpgp.key.readArmored(document.getElementById("pubkey2").value).keys[0],
            message1 = document.getElementById("message1").value,
            message2 = document.getElementById("message2").value,
            encrypted;

        // TODO: More flexibility by finding keys that better fit the message lengths
        var keys = await findKeys();
            
        console.log("Prepare first message");
        
        // [tag,length,'u',length,'msg.txt',date,data]

        var length1 = message1.length + 13,
            length2 = length1 ^ keys[0].o1[1] ^ keys[1].o1[1],
            blocks = Math.floor((length2 + 2) / 16),
            dummy1Length = blocks * 16 - length1 - 6,
            overflow = (length2 + 2) % 16,
            dummy2Length = overflow + message2.length + 15;
        
        console.log(length1, length2);
    
        var literal = new openpgp.packet.Literal();
        literal.setText(message1);
        message1 = openpgp.util.concatUint8Array([
            new Uint8Array([0xcb, length1]), 
            literal.write(), 
            new Uint8Array([0xca,dummy1Length]),
            await openpgp.crypto.random.getRandomBytes(dummy1Length), 
            new Uint8Array([0xca, dummy2Length])
        ]);
        // Let's see which tag works best
        
        console.log("Encrypt first message");
        
        encrypted = openpgp.crypto.cfb.encrypt(keys[0].o0, 'aes256', message1, keys[0].K, true);
        
        console.log("Prepare second message");
        
        literal.setText(message2);
        message2 = openpgp.util.concatUint8Array([
            await openpgp.crypto.random.getRandomBytes(overflow), 
            new Uint8Array([0xcb, message2.length + 15]), 
            literal.write()]);
        
        encrypted = openpgp.util.concatUint8Array([encrypted,
            openpgp.crypto.cfb.normalEncrypt('aes256', keys[1].K, message2, encrypted.subarray(-16))]);
        
        console.log("Encrypt second message");
        
        console.log("Concatenate ciphertexts");
    
        var list = new openpgp.packet.List();
        
        var se = new openpgp.packet.SymmetricallyEncrypted();
        se.encrypted = encrypted;
        list.push(se);
        
        console.log("Encrypt symmetric keys");
        var x=await openpgp.message.encryptSessionKey(keys[0].K, 'aes256', [pubkey1]);
        list.concat((await openpgp.message.encryptSessionKey(keys[0].K, 'aes256', [pubkey1])).packets);
        list.concat((await openpgp.message.encryptSessionKey(keys[1].K, 'aes256', [pubkey2])).packets);
        
        console.log("Compose PGP message packets");
        
        console.log("Armor PGP message");
        
        document.getElementById("pgpmessage").value = (new openpgp.message.Message(list)).armor();
        
    }
    
    function decrypt(){
        console.log("Decrypting message");
        
        var privkey1 = document.getElementById("privkey1").value,
            privkey2 = document.getElementById("privkey2").value,
            pgpmessage = document.getElementById("pgpmessage").value;
        
        if (pgpmessage.length > 0) {
            
            console.log("Decrypting first message");
            openpgp.decrypt({
                message: openpgp.message.readArmored(pgpmessage),
                privateKeys: openpgp.key.readArmored(privkey1).keys
            }).then(function(plaintext) {
                document.getElementById("decrypted1").value = plaintext.data;
            });
            
            console.log("Decrypting second message");
            openpgp.decrypt({
                message: openpgp.message.readArmored(pgpmessage),
                privateKeys: openpgp.key.readArmored(privkey2).keys
            }).then(function(plaintext) {
                document.getElementById("decrypted2").value = plaintext.data;
            });
        }
    }
    
    return {
        'genAsymKeys': genAsymKeys,
        'genSymKeys': findKeys,
        'encrypt': encrypt,
        'decrypt': decrypt
    }
}()

document.getElementById("genasymkey").addEventListener("click", twoforone.genAsymKeys);

document.getElementById("gensymkey").addEventListener("click", twoforone.genSymKeys);

document.getElementById("encrypt").addEventListener("click", twoforone.encrypt);

document.getElementById("decrypt").addEventListener("click", twoforone.decrypt);