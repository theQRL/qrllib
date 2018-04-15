const assert = require('assert');
const crypto = require('crypto');
const libqrl = require('./tmp/libjsqrl.js');

// TODO: Move this to another file with all the helper functions

function ToArray(vec)
{
    let arr = new Uint8Array(vec.size());
    for(let i=0; i<vec.size(); i++)
    {
        arr[i]=vec.get(i);
    }
    return arr;
}

function Uint8VectorToUint8Array(vec)
{
    let arr = new Uint8Array(vec.size());
    for(let i=0; i<vec.size(); i++)
    {
        arr[i]=vec.get(i);
    }
    return arr;
}

function ToUint8Vector(arr)
{
    let vec = new libqrl.Uint8Vector();
    for(let i=0; i<arr.length; i++)
    {
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
            for(let i=0; i<tmp_vec.size(); i++)
            {
                assert.equal(i+1, tmp_vec.get(i) );
            }
        });
    });

    describe('helpers', function () {
        it('data -> vec', function () {
            tmp_vec = ToUint8Vector([1, 2, 3, 4, 5]);

            assert.equal(5, tmp_vec.size());
            for(let i=0; i<tmp_vec.size(); i++)
            {
                assert.equal(i+1, tmp_vec.get(i) );
            }
        });
    });

    describe('helpers', function () {
        it('data -> vec', function () {
            tmp_vec = ToUint8Vector([1, 2, 3, 4, 5]);
            tmp_arr = ToArray(tmp_vec);

            assert.equal(5, tmp_arr.length);
            for(let i=0; i<tmp_arr.length; i++)
            {
                assert.equal(i+1, tmp_arr[i] );
            }
        });
    });

    describe('bin2mnemonic', function () {
        it('[0,1,2,3,4,5] should return aback bag adrift dream', function () {
            data = ToUint8Vector([0, 1, 2, 3, 4, 5]);
            assert.equal('aback bag adrift dream', libqrl.bin2mnemonic(data) );
        });

        it('[1,2,3] should return aback bag', function () {
            data = ToUint8Vector([0, 1, 2]);
            assert.equal('aback bag', libqrl.bin2mnemonic(data) );
        });

        it('aback bag to binary and back', function () {
            tmp_bin = libqrl.mnemonic2bin('aback bag');
            tmp_mnemonic = libqrl.bin2mnemonic(tmp_bin);

            assert.equal('aback bag', tmp_mnemonic );
        });
    });


    describe('xmss', function () {
        it('create tree', function () {

            let seed_vector = ToUint8Vector(new Uint8Array(48));
            let height = 4;
            let hash_func = libqrl.eHashFunction.SHA2_256;

            xmss = libqrl.Xmss.fromParameters(seed_vector, height, hash_func);

            address = libqrl.bin2hstr(xmss.getAddress());
            assert.equal(
                address,
                '00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de');
 
            assert.equal(
                4,
                xmss.getHeight()
            )
        });
    });
});
