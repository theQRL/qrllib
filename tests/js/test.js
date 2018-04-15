var assert = require('assert');
var libqrl = require('./tmp/libjsqrl.js');

describe('libjsqrl', function () {
    describe('bin2mnemonic', function () {
        it('[0,1,2,3,4,5] should return aback bag adrift dream', function () {
            data = new libqrl.VectorUChar();
            for (let i = 0; i < 6; i++) {
                data.push_back(i);
            }
            assert.equal('aback bag adrift dream', libqrl.bin2mnemonic(data) );
        });

        it('[1,2,3] should return aback bag', function () {
            data = new libqrl.VectorUChar();
            for (let i = 0; i < 3; i++) {
                data.push_back(i);
            }
            assert.equal('aback bag', libqrl.bin2mnemonic(data) );
        });
    });

});
