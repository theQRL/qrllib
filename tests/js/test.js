const assert = require('assert');
const crypto = require('crypto');
const libqrl = require('./tmp/libjsqrl.js');

// TODO: Move this to another file with all the helper functions

function ToArray(vec) {
    let arr = new Uint8Array(vec.size());
    for (let i = 0; i < vec.size(); i++) {
        arr[i] = vec.get(i);
    }
    return arr;
}

function ToUint8Vector(arr) {
    let vec = new libqrl.Uint8Vector();
    for (let i = 0; i < arr.length; i++) {
        vec.push_back(arr[i])
    }
    return vec;
}

describe('libjsqrl', function () {
    describe('helpers', function () {
        it('arr -> vec', function () {
            tmp_arr = Uint8Array.from([1, 2, 3, 4, 5]);
            tmp_vec = ToUint8Vector(tmp_arr);

            assert.equal(5, tmp_vec.size());
            for (let i = 0; i < tmp_vec.size(); i++) {
                assert.equal(i + 1, tmp_vec.get(i));
            }
        });
        it('data -> vec', function () {
            tmp_vec = ToUint8Vector([1, 2, 3, 4, 5]);

            assert.equal(5, tmp_vec.size());
            for (let i = 0; i < tmp_vec.size(); i++) {
                assert.equal(i + 1, tmp_vec.get(i));
            }
        });
        it('data -> vec', function () {
            tmp_vec = ToUint8Vector([1, 2, 3, 4, 5]);
            tmp_arr = ToArray(tmp_vec);

            assert.equal(5, tmp_arr.length);
            for (let i = 0; i < tmp_arr.length; i++) {
                assert.equal(i + 1, tmp_arr[i]);
            }
        });
    });

    describe('sha2_256', function () {
        it('hello', function () {
            data = [1,2,3,4,5];

            data_vec = ToUint8Vector(data);
            hash_vec = libqrl.sha2_256( data_vec );

            assert.equal(32, ToArray(hash_vec).length);
            assert.equal(
                libqrl.bin2hstr( hash_vec ),
                '74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0');
        });
    });

    describe('address from epk', function () {
        it('basic', function () {
            let expected_address = 'Q000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879';

            // Object a
            let hexseed = '0002006963291e58d6e776fe25932964748e774fb22cff112fbf5ece45b17965704697550064a60f40ba7c742694346761d5cc';
            xmss = libqrl.Xmss.fromHexSeed(hexseed);
            epk = xmss.getPK();

            address = 'Q'+libqrl.getAddress(epk);

            assert.equal(expected_address, address);
        });
    });

    describe('bin2mnemonic', function () {
        it('[0,1,2,3,4,5] should return aback bag adrift dream', function () {
            data = ToUint8Vector([0, 1, 2, 3, 4, 5]);
            assert.equal('aback bag adrift dream', libqrl.bin2mnemonic(data));
        });

        it('[1,2,3] should return aback bag', function () {
            data = ToUint8Vector([0, 1, 2]);
            assert.equal('aback bag', libqrl.bin2mnemonic(data));
        });

        it('aback bag to binary and back', function () {
            tmp_bin = libqrl.mnemonic2bin('aback bag');
            tmp_mnemonic = libqrl.bin2mnemonic(tmp_bin);

            assert.equal('aback bag', tmp_mnemonic);
        });
    });

    describe('xmss', function () {
        it('create tree from parameters', function () {

            let seed_vector = ToUint8Vector(new Uint8Array(48));
            let height = 4;
            let hash_func = libqrl.eHashFunction.SHA2_256;

            xmss = libqrl.Xmss.fromParameters(seed_vector, height, hash_func);

            ///////////////////////////

            assert.equal(0, xmss.getIndex());

            assert.equal(4, xmss.getHeight());

            assert.equal(
                xmss.getAddress(),
                'Q00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de');

            assert.equal(
                libqrl.bin2hstr(xmss.getAddressRaw()),
                '00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de');

            assert.equal(
                xmss.getHexSeed(),
                '000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000');

            assert.equal(
                xmss.getMnemonic(),
                'aback bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback ' +
                'aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback');
        });

        it('create tree from hexseed', function () {
            let hexseed = '0002006963291e58d6e776fe25932964748e774fb22cff112fbf5ece45b17965704697550064a60f40ba7c742694346761d5cc';
            xmss = libqrl.Xmss.fromHexSeed(hexseed);

            ///////////////////////////

            assert.equal(0, xmss.getIndex());

            assert.equal(4, xmss.getHeight());

            assert.equal(
                xmss.getAddress(),
                'Q000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879');

            assert.equal(
                libqrl.bin2hstr(xmss.getAddressRaw()),
                '000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879');

            assert.equal(
                xmss.getHexSeed(),
                '0002006963291e58d6e776fe25932964748e774fb22cff112fbf5ece45b17965704697550064a60f40ba7c742694346761d5cc');

            assert.equal(
                xmss.getMnemonic(),
                'aback bunny heroic crazy brown miss torch inhere cater crazy hammer ethic kidnap wire clutch vat cope '+
                'walnut sodden gather lame free enable juicy aboard exert awhile artful leg during neatly employ gritty gill');
        });

        it('create tree from mnemonic', function () {

            let mnemonic =
                'aback bunny heroic crazy brown miss torch inhere cater crazy hammer ethic kidnap wire clutch vat cope '+
                'walnut sodden gather lame free enable juicy aboard exert awhile artful leg during neatly employ gritty gill';

            xmss = libqrl.Xmss.fromMnemonic(mnemonic);

            ///////////////////////////

            assert.equal(0, xmss.getIndex());

            assert.equal(4, xmss.getHeight());

            assert.equal(
                xmss.getAddress(),
                'Q000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879');

            assert.equal(
                libqrl.bin2hstr(xmss.getAddressRaw()),
                '000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879');

            assert.equal(
                xmss.getHexSeed(),
                '0002006963291e58d6e776fe25932964748e774fb22cff112fbf5ece45b17965704697550064a60f40ba7c742694346761d5cc');

            assert.equal(
                xmss.getMnemonic(),
                'aback bunny heroic crazy brown miss torch inhere cater crazy hammer ethic kidnap wire clutch vat cope '+
                'walnut sodden gather lame free enable juicy aboard exert awhile artful leg during neatly employ gritty gill');
        });

        it('get height from address', function () {
            let some_address = 'Q00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de';
            assert.equal(libqrl.getHeight(some_address), 4);
        });

        it('get hash function from address', function () {
            let some_address = 'Q00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de';

            hash_function = libqrl.getHashFunction(some_address);
            assert.equal(hash_function, libqrl.eHashFunction.SHA2_256);
        });

        it('get signature type from address', function () {
            let some_address = 'Q00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de';

            signature_type = libqrl.getSignatureType(some_address);

            assert.equal(signature_type, libqrl.eSignatureType.XMSS);
        });

        it('get descriptor', function () {
            let some_address = 'Q0105000c10421ed6eebb1fb8f066ac50678961f60b516d98ab83bee92278f6fd238306e1424918';

            assert.equal(libqrl.getHeight(some_address), 10);
            assert.equal(libqrl.getHashFunction(some_address), libqrl.eHashFunction.SHAKE_128);
            assert.equal(libqrl.getSignatureType(some_address), libqrl.eSignatureType.XMSS);
        });

    });
});
