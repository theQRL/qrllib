// QRLLIB Browser Tests
const { test, expect } = require('@playwright/test');

let libqrl;

test.describe('libjsqrl browser tests', () => {
    test.beforeAll(async ({ browser }) => {
        // We'll initialize libqrl in each test instead since Playwright
        // doesn't maintain page state across tests like Cypress does
    });

    test.beforeEach(async ({ page }) => {
        // Visit the test HTML page that loads the library
        await page.goto('/tests/js/test.html');

        // Wait for the library to be loaded and initialized
        await page.waitForFunction(() => window.libqrl !== null && window.libqrl !== undefined);

        // Ensure the WASM module is ready
        await page.waitForFunction(() => {
            if (window.libqrl.calledRun) {
                return true;
            }
            return false;
        }, { timeout: 30000 });

        // Get libqrl reference for the test
        libqrl = await page.evaluate(() => window.libqrl);
    });

    test.describe('helpers', () => {
        test('arr -> vec', async ({ page }) => {
            const result = await page.evaluate(() => {
                const tmp_arr = Uint8Array.from([1, 2, 3, 4, 5]);
                const tmp_vec = window.ToUint8Vector(tmp_arr);

                const size = tmp_vec.size();
                const values = [];
                for (let i = 0; i < tmp_vec.size(); i++) {
                    values.push(tmp_vec.get(i));
                }
                return { size, values };
            });

            expect(result.size).toBe(5);
            for (let i = 0; i < result.values.length; i++) {
                expect(result.values[i]).toBe(i + 1);
            }
        });

        test('data -> vec', async ({ page }) => {
            const result = await page.evaluate(() => {
                const tmp_vec = window.ToUint8Vector([1, 2, 3, 4, 5]);

                const size = tmp_vec.size();
                const values = [];
                for (let i = 0; i < tmp_vec.size(); i++) {
                    values.push(tmp_vec.get(i));
                }
                return { size, values };
            });

            expect(result.size).toBe(5);
            for (let i = 0; i < result.values.length; i++) {
                expect(result.values[i]).toBe(i + 1);
            }
        });

        test('vec -> arr', async ({ page }) => {
            const result = await page.evaluate(() => {
                const tmp_vec = window.ToUint8Vector([1, 2, 3, 4, 5]);
                const tmp_arr = window.ToArray(tmp_vec);

                return { length: tmp_arr.length, values: Array.from(tmp_arr) };
            });

            expect(result.length).toBe(5);
            for (let i = 0; i < result.values.length; i++) {
                expect(result.values[i]).toBe(i + 1);
            }
        });
    });

    test.describe('sha2_256', () => {
        test('hello', async ({ page }) => {
            const result = await page.evaluate(() => {
                const data = [1, 2, 3, 4, 5];
                const data_vec = window.ToUint8Vector(data);
                const hash_vec = window.libqrl.sha2_256(data_vec);

                return {
                    length: window.ToArray(hash_vec).length,
                    hash: window.libqrl.bin2hstr(hash_vec)
                };
            });

            expect(result.length).toBe(32);
            expect(result.hash).toBe('74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0');
        });
    });

    test.describe('address from epk', () => {
        test('basic', async ({ page }) => {
            const result = await page.evaluate(() => {
                const expected_address = 'Q000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879';
                const hexseed = '0002006963291e58d6e776fe25932964748e774fb22cff112fbf5ece45b17965704697550064a60f40ba7c742694346761d5cc';
                const xmss = window.libqrl.Xmss.fromHexSeed(hexseed);
                const epk = xmss.getPK();
                const address = 'Q' + window.libqrl.getAddress(epk);

                return { expected: expected_address, actual: address };
            });

            expect(result.actual).toBe(result.expected);
        });
    });

    test.describe('bin2mnemonic', () => {
        test('[0,1,2,3,4,5] should return aback bag adrift dream', async ({ page }) => {
            const mnemonic = await page.evaluate(() => {
                const data = window.ToUint8Vector([0, 1, 2, 3, 4, 5]);
                return window.libqrl.bin2mnemonic(data);
            });

            expect(mnemonic).toBe('aback bag adrift dream');
        });

        test('[1,2,3] should return aback bag', async ({ page }) => {
            const mnemonic = await page.evaluate(() => {
                const data = window.ToUint8Vector([0, 1, 2]);
                return window.libqrl.bin2mnemonic(data);
            });

            expect(mnemonic).toBe('aback bag');
        });

        test('aback bag to binary and back', async ({ page }) => {
            const mnemonic = await page.evaluate(() => {
                const tmp_bin = window.libqrl.mnemonic2bin('aback bag');
                return window.libqrl.bin2mnemonic(tmp_bin);
            });

            expect(mnemonic).toBe('aback bag');
        });
    });

    test.describe('xmss', () => {
        test('create tree from parameters', async ({ page }) => {
            const result = await page.evaluate(() => {
                const seed_vector = window.ToUint8Vector(new Uint8Array(48));
                const height = 4;
                const hash_func = window.libqrl.eHashFunction.SHA2_256;

                const xmss = window.libqrl.Xmss.fromParameters(seed_vector, height, hash_func);

                return {
                    index: xmss.getIndex(),
                    height: xmss.getHeight(),
                    address: xmss.getAddress(),
                    addressRaw: window.libqrl.bin2hstr(xmss.getAddressRaw()),
                    hexSeed: xmss.getHexSeed(),
                    mnemonic: xmss.getMnemonic()
                };
            });

            expect(result.index).toBe(0);
            expect(result.height).toBe(4);
            expect(result.address).toBe('Q00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de');
            expect(result.addressRaw).toBe('00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de');
            expect(result.hexSeed).toBe('000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000');
            expect(result.mnemonic).toBe(
                'aback bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback ' +
                'aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback'
            );
        });

        test('create tree from hexseed', async ({ page }) => {
            const result = await page.evaluate(() => {
                const hexseed = '0002006963291e58d6e776fe25932964748e774fb22cff112fbf5ece45b17965704697550064a60f40ba7c742694346761d5cc';
                const xmss = window.libqrl.Xmss.fromHexSeed(hexseed);

                return {
                    index: xmss.getIndex(),
                    height: xmss.getHeight(),
                    address: xmss.getAddress(),
                    addressRaw: window.libqrl.bin2hstr(xmss.getAddressRaw()),
                    hexSeed: xmss.getHexSeed(),
                    mnemonic: xmss.getMnemonic()
                };
            });

            expect(result.index).toBe(0);
            expect(result.height).toBe(4);
            expect(result.address).toBe('Q000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879');
            expect(result.addressRaw).toBe('000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879');
            expect(result.hexSeed).toBe('0002006963291e58d6e776fe25932964748e774fb22cff112fbf5ece45b17965704697550064a60f40ba7c742694346761d5cc');
            expect(result.mnemonic).toBe(
                'aback bunny heroic crazy brown miss torch inhere cater crazy hammer ethic kidnap wire clutch vat cope ' +
                'walnut sodden gather lame free enable juicy aboard exert awhile artful leg during neatly employ gritty gill'
            );
        });

        test('create tree from mnemonic', async ({ page }) => {
            const result = await page.evaluate(() => {
                const mnemonic =
                    'aback bunny heroic crazy brown miss torch inhere cater crazy hammer ethic kidnap wire clutch vat cope ' +
                    'walnut sodden gather lame free enable juicy aboard exert awhile artful leg during neatly employ gritty gill';

                const xmss = window.libqrl.Xmss.fromMnemonic(mnemonic);

                return {
                    index: xmss.getIndex(),
                    height: xmss.getHeight(),
                    address: xmss.getAddress(),
                    addressRaw: window.libqrl.bin2hstr(xmss.getAddressRaw()),
                    hexSeed: xmss.getHexSeed(),
                    mnemonic: xmss.getMnemonic()
                };
            });

            expect(result.index).toBe(0);
            expect(result.height).toBe(4);
            expect(result.address).toBe('Q000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879');
            expect(result.addressRaw).toBe('000200baea487e62a96f32a2c427def90f020880d2fb0bff756ff6450186904dcc0c88e9018879');
            expect(result.hexSeed).toBe('0002006963291e58d6e776fe25932964748e774fb22cff112fbf5ece45b17965704697550064a60f40ba7c742694346761d5cc');
            expect(result.mnemonic).toBe(
                'aback bunny heroic crazy brown miss torch inhere cater crazy hammer ethic kidnap wire clutch vat cope ' +
                'walnut sodden gather lame free enable juicy aboard exert awhile artful leg during neatly employ gritty gill'
            );
        });

        test('get height from address', async ({ page }) => {
            const height = await page.evaluate(() => {
                const some_address = 'Q00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de';
                return window.libqrl.getHeight(some_address);
            });

            expect(height).toBe(4);
        });

        test('get hash function from address', async ({ page }) => {
            const result = await page.evaluate(() => {
                const some_address = 'Q00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de';
                const hash_function = window.libqrl.getHashFunction(some_address);
                return {
                    hash_function,
                    expected: window.libqrl.eHashFunction.SHA2_256
                };
            });

            expect(result.hash_function).toBe(result.expected);
        });

        test('get signature type from address', async ({ page }) => {
            const result = await page.evaluate(() => {
                const some_address = 'Q00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de';
                const signature_type = window.libqrl.getSignatureType(some_address);
                return {
                    signature_type,
                    expected: window.libqrl.eSignatureType.XMSS
                };
            });

            expect(result.signature_type).toBe(result.expected);
        });

        test('get descriptor', async ({ page }) => {
            const result = await page.evaluate(() => {
                const some_address = 'Q0105000c10421ed6eebb1fb8f066ac50678961f60b516d98ab83bee92278f6fd238306e1424918';

                return {
                    height: window.libqrl.getHeight(some_address),
                    hashFunction: window.libqrl.getHashFunction(some_address),
                    signatureType: window.libqrl.getSignatureType(some_address),
                    expectedHashFunction: window.libqrl.eHashFunction.SHAKE_128,
                    expectedSignatureType: window.libqrl.eSignatureType.XMSS
                };
            });

            expect(result.height).toBe(10);
            expect(result.hashFunction).toBe(result.expectedHashFunction);
            expect(result.signatureType).toBe(result.expectedSignatureType);
        });
    });

    test.describe('XMSSBasic (variable WOTS)', () => {
        test('create xmss tree from parameters using WOTS param W = 4', async ({ page }) => {
            const pk = await page.evaluate(() => {
                const a = new Uint8Array(48); // null-seed
                const height = 6;
                const WOTSParamW = 4;
                const xmss_basic_object = window.libqrl.XmssBasic.fromParameters(
                    window.ToUint8Vector(a),
                    height,
                    window.libqrl.eHashFunction.SHAKE_128,
                    window.libqrl.eAddrFormatType.SHA256_2X,
                    WOTSParamW
                );
                return xmss_basic_object.getPK();
            });

            expect(pk).toBe('010300884181fe54232c3cf17c4683b6d451e9d4f54b624f11e476732bc5bbe63d9dc53191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d');
        });

        test('get height from created tree', async ({ page }) => {
            const height = await page.evaluate(() => {
                const a = new Uint8Array(48);
                const height = 6;
                const WOTSParamW = 4;
                const xmss_basic_object = window.libqrl.XmssBasic.fromParameters(
                    window.ToUint8Vector(a),
                    height,
                    window.libqrl.eHashFunction.SHAKE_128,
                    window.libqrl.eAddrFormatType.SHA256_2X,
                    WOTSParamW
                );
                return xmss_basic_object.getHeight();
            });

            expect(height).toBe(6);
        });

        test('get and set index from created tree', async ({ page }) => {
            const result = await page.evaluate(() => {
                const a = new Uint8Array(48);
                const height = 6;
                const WOTSParamW = 4;
                const xmss_basic_object = window.libqrl.XmssBasic.fromParameters(
                    window.ToUint8Vector(a),
                    height,
                    window.libqrl.eHashFunction.SHAKE_128,
                    window.libqrl.eAddrFormatType.SHA256_2X,
                    WOTSParamW
                );

                const initialIndex = xmss_basic_object.getIndex();
                xmss_basic_object.setIndex(1);
                const afterSetIndex = xmss_basic_object.getIndex();
                xmss_basic_object.setIndex(0);
                const finalIndex = xmss_basic_object.getIndex();

                return { initialIndex, afterSetIndex, finalIndex };
            });

            expect(result.initialIndex).toBe(0);
            expect(result.afterSetIndex).toBe(1);
            expect(result.finalIndex).toBe(0);
        });

        test('can correctly sign a message', async ({ page }) => {
            const result = await page.evaluate(() => {
                const a = new Uint8Array(48);
                const height = 6;
                const WOTSParamW = 4;
                const xmss_basic_object = window.libqrl.XmssBasic.fromParameters(
                    window.ToUint8Vector(a),
                    height,
                    window.libqrl.eHashFunction.SHAKE_128,
                    window.libqrl.eAddrFormatType.SHA256_2X,
                    WOTSParamW
                );

                const expectedSig = '0000000010ddfc3f7bfb9c95cc48f4cfac1eff2cbb03c0d0647e41a84de8d3ecebfe0bc2376114b2a7043809d74e9f328971947302c85d73a8c757bd98356cb26d1822b1e2b46ac1b2d810e772dd6af8a4db3e3ba915956f0cbbf06799ef23bc181f6973a0dec9ab2327c9d7e5dcfa3c25db2013525efc5f7a90e4519f2d91506d83cab849ad8c3741754afbc92f8b83bcf97794658053da9dc94565adee8140272801a7f75b1ffd3930132f207c389b5b06695e9a2177581fa9a1f7b76e811dba4fb05664dce5819e0a0dbbf27225e74c746f19bd6fadc0caf7815333e6321f11e377daf558f2cf79dfcf4f16e67b53fd335e1e925cb7fe3763ec1619e523e9d194b25fe19a050534f8cbfb5f52b2f399c82554a1f5a6adeb8954060465244973839add319a116216e2fa1371239cf07556f06a941c1b0b66d83374d15f80e4e8ff14b5f60cafd8a0e4be4d145a837b5eec05a990ef8bfbaf497d72caea4b6489a359b9b3ceab6188970e739163ce5b55d8e5f1409ff3ae5f247f41c6ac637404e1b742b62e41c35d9e0461e1b61d7b3713ac159dd08cff8037980bff7bb7fce82802f2a2d9352d501224d1fa0db285ab3cd5956ba52d7c8dfbf9577f8568e67e8dbfc16af416ab9ae4274f55c77af1e5f0dc523f7fdab74ebf76cecfed2452f9de7fda4cf5c6545ad6de11d0639ce479b13cdbcedcf98b0e0cc8e2978139c7d9f0ca3734bfb7fb7e35cb54bcb0c44802389c8e31ffd6078be895e0e917bed98e48d032f8f4a8950a187156cdd97677bc725e639b73d45dc1e2c39af5ebb8b3072fef26af5814a1d02c45861ec2f9987350e339ea436572fd4fb74e27547a3ffb7959b92b5be3cf032183fba0f85befd35cf1147ac819cdec7397190a8060b17b8f45666d3546a3403414d1a79003b9b5de6b4edf7ceb761373424929616cf10c6b39932a478a4840ffbe1b53f2f2a0e3edacb1ab516c19df0cb17e54a5477aefd560b090bc7eda8239fd7dba50fd5b604e1474d4145edb07feb94d28060e570db210d80bd3f2905539f9c7da327f9297ffc989004656ec03e12b839e91d2455bd9ef04acaa4a37cd4d018b3a0dc11653ac679434631d7b27247feca64a8a05d971d4b3ddcc1d6afa7da28d6dd99e6ea185a7704b8cd0b856acc97629a3b4e6fc1e995d22475bd51401c29d2b5f63e949ab382305c57a63e8c1bd3141294fd760b0fcbdd275752b8ed914d90bc685ce572a83032f04f266d8bb14f450917c91cc83c7e460c61fe5b4f6cb65109f6dd55365ed157d1d1cf917852285dc5804c06d82cb753ed6ecc7d90b03c6395f4bcbfd448471388f313fae4c2bbf646f4ec28f70c15be663a552f96bb77866977cd04803d59622fc374827b62cf68d11b0ce114b7d916ea12304f54ef6d7f6222010f6666df77734e9a358fe5270fa1f405984f4e8432da01ffa7eb79f99ad532fa65ee69ba0c2f3e51a43e2565c2354522322c662a68168d549d65ba242da9dea38c8d35a41e3a008647f25616c68f915a4518ca4eae161ce66659f52aed1b8d25dc3c50ce3ca4eb253f791956ad601a2f6e3f9490ccd98ec8a5efce427889b50834ea5169189e4144c9563cdb3b76ecd043a6a15d4f85026b41f2de62da06319a9046fe68bd4c281ff4e81ba7527a91e04566603dbb065fa586392ec6b3bc2f7fdc71b2c7ec0bca9286a9cfd51b2e40d647ce3d8ae45d291f2a0730d308c567eeb7239057e0cbe8736415e9cebd7dae08ed642e7541e86b36da1c39a62e79d35c88a792c20f297a2dfacbc18fd799f9bec72c0e714eb6a33cfc6439e603d8e0aff5332e69d9301eecd85360c3a94ad1715bbd32b24b0eb36807393771745f389f0b5339d3494c42a0bfd7876cb36a82c6fe096e79cd3b4f5169f96d0ec4225039f13ff89753be03ee3cc57ac4c7592edad9ef815b76c3c638ee54c22ca2816fbef9742dff761eae2772dfef9f62de57529cd121e4d35c87dc6fbd1bb057ccb299b9a5090df02cd2fa7d380106e8d20d7b38ff740031de090c2898b645613b9b5d5d5e73e5f5773437a5943477116e2ce9f51f0a47b576cdf698dd5ebd23b006309128f9816cb3f8933573f38b88557efdb5ce09e5063f4d55e589a9c68fe1d0cdd3316e7b0e6edd2c9dcb40627476fbc46c32b7aab1b3d405decd7032c4c6e80df97d7aba9ed18cda4bfb131dd4c4f4442bd43bf99ee28476c90c728d917267cf6b9009777c91b81cab6cca4cc2200bdb031b68a0d84e40ca5f1162b08c241956792855ea29712c79ffbeb04df32d027fb68da3b664f3b3a872d881223c2a19b27666bfc589372db27ad7e3c8269bc21c4c2b842fd07c25f85efe8c7a933959c9712d298dc03d13c5d2f568ad499a6e6b44b03aa1c8b664339f0595b3c83d589cac947c92fafaed443a52ed55b8be54a841eccb526f6a344caca411e3df34c251811d49a0d19bdd851475555bb07028dbdd955fd60d1ca90c4991058345470ae46d5dd652debae7b832994b09764d55f0637870b309a1f7de9bb372d42d93d41a13db77f3cabd5f7be8166c10bf208ff5c08674e5124890410b7eea3789ed1c796368056ccc1870804e0e525cb35e68678fe09657462b0e8da22c1f8955ac38a1af976db5cd8e3c29a2f33c2921cec298d2b736d54367143abe3caffa4bc181bc8fa4da3052a3c04a2cf02d7100fd946bd8ab9ba38041bb999a00a5f50313d034db1a92ca4a128aa2bb855a827eca2fecd9c0002452fa0a03735f03f38751c0bc64ce04905071b76d9cce03eeec0eefe821a028f4d18dfb2e8d11563c6eec1b08ae78118ac3d62d79540ecec0e11f9fc5f51d2fb3869991a4c149c1499c61a29d219f5e8295ae87b188d1596a414907a70176741672f1bb7e9a18a2cf7d1cad5f81d15f7be3bef547d49fa086b3fcecc4f2071fcb2a957229e5da35302854b6aabb7b6b0206689a3dba0e5f761dac2b2ed9d0f69b779d5596ccc61f9e1dc2ba8beef215f9c8ea015fab33bef1b9c62d091280192d312c4acf34081f91e6a49665f7afac5aa0714a68dc3efa37861b8accb1d16700ed1dc3c43c9c67ceea797280a757aec9fb93d9150c8ac64f83751ce839d2a0097efa3444c89adf9647a0d3dc09d0b33bb9ea656496cc1a3bc2f89470a22e53fb51f9d1dde2364c5b36f87ff4e3e9dbccac7c6b0bec362e1269c5ff1eff368924f91f16bc78e6ee09cc637e9e381aefade77fdb5e902f4688a0c0e070cc34ec5fc5ad84bab4ad8736f11836d4431632c5326c59ea680e850efe9f2755beeb52f9ae87576df6b9b8d22c747bad88aee5a21c53b5253d2b013446118fe7cb6d83283965ed39f7bbd8776758c95550275afe2b8ff7549ebda338855835ffe37cb1c85f5a66aedf73246fcbe3bb9dfb48a3ff1b20531ff1bfaa1ce337c52e6912a5f12a3aa3a36b3f5d0c163e9d1d62ab3d9acf0be4ea9ee6899c2778661413e932230573a9bceecac205a85d5c927a4ac0fe6c5bca65e532b444f0b121df20c81c72536cb07f0ac8cd03d54d644e0fa4a9c293bd74259955531319e5bb0d5762435a4604b39d85b8ab87451a457fe6e01ea5d5318958a14d34d87b5026dba1685b64937940c0dede517fa224f3533efc69d1e45be3ba33f4effa645e44452bc8b9ff9248b37390dd14f5ed668c2b6339d285466d97774c9e98c216853270410a0e69eaa89bc108d9086cdae440355679c797712af127519a6195169b6914038ed21aad0f5dfa980bb3b2755cbe88369d0431bcf5c7d96824e1df9c35a4a164e676d6b0dcf65e28cb2d439033fc72115695ad3c7a47f0304efc61934cf27247e6f7b99cd8072fe83e406117c5acad001f7a846afaecc0849aa9361c688f2e524fef98e5498a7c9d085f4ac3a745a005105923e45eda66159ed58b7651b075ca925bed45714d4382212925fbea79d8ceed4f4c89e16f69372fbfeea7f5adc4389e47d391802620bd9543bacc9afe8132e78b408fd116206d8a6cf385bb687616369be08698d66ca713ca929fb4d1f9f4411e203040d4fd119f3220e808b00ac213138c5afba22ebcfe21713e071d83f1b43e4b5a8518e5fb62bb9344cbffa2d91c75a99bdd6654d7b921b0af41ba19382c13889fde15c4ab3a184b28aae2ba93c312119b15dd436ffee429e1b54b4e616bf5484e166cfa23efd952a8e0eada19caa7053b770730d4c951376fb1e6eb8551a360be0195efbf9a5f13fb5dd1771c8b868a2f4c50ba8383d07ce2834b10a36356fdb03d85e10af49e3a7e3c6e11ee13128d1fbd2f3b5f3818ebf8ab1635a63673346b3ee0257f170ad9c3ddee6633d12e189e816aa5f98343fbc3caa789fbbf68e3571139cffeb999430e238f2fe2e95927649804b7f64ff1666b589f6f4c87b8967bf8f5bd8aa7f29987009cb989f66f81693e5148ad40f9d2438295d3b31f5dcd388dcb036a3fccd975c0401425563b525804e14c866b62ed9ca9e848f156f5da438322a0fceb1d6a0aa59ff8c25380f03fcafc81de7341a4b93423ff2553969f687fe02fe39963e03817dc246ba7fadb653724c0d8a6b1805537bc36e285a7f23d6be7c247dc0eac355c571aa7f700cc1ac737994641edbec6a9b984e3447ef14ffd8a49a6c134b3b7ce913bdca18a5e35c2c8d7b94adc4df3401c3043f1bde4727560e2978de176e5311acf59dc2b97493f37b93587932a4d9a4315787311ed2e0b0cf634c6cb10649b74f36c210cb1804a5d21755bda186411e297dca1e6f9daa1fca1730096ece27ac13f7b2dadf92f5d377a7a0339c7d7e0d12727ed60582aac9037fe9b7b69dcbd9c7a366d29e30b349bc9870df7caf012a71a3a7a5554a61ad70807f85b7471529e50e52895ef5ea26dad5a95b563cc4bbc2f1ee08f50c422ecea2caacfb3fa7d1b53781f11f5e308765fd717aa1ae90d0e50b0368874bf53f65b4fcb02b8be1a5ec31d70c92099d72da2528aabd2319869dea80425b5039791a69ccfed6b5b9a67b8135697d6389652af6b55a5c42631ce7253aa1d97ad761b15bdffaf20a4e2b601ea60d0491b0eb6466b66e6fe878d718318d249a599fe052c796fd1e3badc730914ea59fa61942d222fcdf9ecc0f999c5066a388ed5b55f7ae8a4a4f0bec0f856adaa72a571977c28daf0fdb362a0e61d11abb655a30cac6abfa9d99f5b73aa3b293b4c3e6ea409c3532d3e9aeb483d2c39130434d6765967b41fe9334f4ff82a1eb336951c559d1312b946abcec3f45f14851e0f43fe51fbcd649168f619aa742952033589d71a3280b94e8761c487faebc247169aa7e8655871f1f9cd84345ebbfa47faac5022d1926b345c33d7353145259528e303ba01a5204a7347bcecd9974efd1cbfe4e94e2ba7aeafdc37391c2600983cd0336e84fd69751c9044439a5a5e05c58b74ed624d966d7e6f4f37d82e91bbe08391173df04389aacfb8c6d517ccf81a01bfdf5bde998214b7c59894b8740423631c7ef3e31a933535eb7732682dc9d8298c8b6a5cd698077f05edda37536656ccfdeeeee6039495d9f29459fece731804db76659a8f4366eca3e5916cbf4f273ad879e5c444deaf0ab876e2dee6127a2df11c5b086db9119b007de1cc330944f22cc0b0a8dea53db0155a56ec6b4ebd99a66341d4d1e04c03a38fd657ba3e36c9000853c71fb2e3646fe2312944b5aa9814b1b100a370458dc24c2ac82d1f69470876664fa3486315e356b2e0e264e4efdd0190e042eebe6fe8fa8368da905b631d080d93c5d97837e446a22110a8d9eee1b9cf0bd5f713198865282bcf6da762760a1014ab6f4ede10faaf8d7a548c0a89f1c8c19ff2de72d65ee9506da455678eaa165f5b0bf27ed4b1d7c091cbca8142001a21b72fb6ae2aa63343c6a02a7eb42ce5a99b8b7142e61706d4267d24ee5ac353f9ff1c2fdf309936808cb339e71bd7e8cb106ccd0663484af5573d0ccdb085fc7f915ea6c0e940ecea08eb32a034c537a124b3e3a168aff3d7680f344639af64d63b681be8650f9e982b4345fa0ef5c9af3f2e0d9ffdc6ff7078196301d81f532d769ae0c4e1597a5063d8994bcb139389f9b4193f5df702f93dada6e10a649f33340100a3723b9004125560193307e24e861502ae06a5cd33d1cf9e831ff9d20c8f5ed55134a6238122d053747f455c39a8c2de80f4835f5ff76de61f1ae0388ef4bc4469fcaf78ba97462bebe00d2c126fc3e6aab591eb3b566ab82273a410607b049b3b5acc924d34355220d1c06c1d46b0577319cf6623462c920f940efb5b6c5b15b5b1f119245cf90f74159a176a6fd67e1d65008379ff5c2f1';
                const message = '56454c9621c549cd05c112de496ba32f';

                const messageBin = window.ToUint8Vector(window.hexToBytes(message));
                const signed = xmss_basic_object.sign(messageBin);

                const signedHex = window.bytesToHex(window.binaryToBytes(signed)).toString();

                return { expected: expectedSig, actual: signedHex };
            });

            expect(result.actual).toBe(result.expected);
        });

        test('can correctly verify a message', async ({ page }) => {
            const verification = await page.evaluate(() => {
                const a = new Uint8Array(48);
                const height = 6;
                const WOTSParamW = 4;
                const xmss_basic_object = window.libqrl.XmssBasic.fromParameters(
                    window.ToUint8Vector(a),
                    height,
                    window.libqrl.eHashFunction.SHAKE_128,
                    window.libqrl.eAddrFormatType.SHA256_2X,
                    WOTSParamW
                );

                const sig = '0000000120692da5e9d956be5e1e1d2aa5f9b169592112e4d978f96721ac58ab6cb6f1b5d41a49857b33254a0e17cdb2dc83f2552f21e4867c270041c71d861f23ec5aad061850dbf8c74f98240031d62099c1544aeff3b6502c23cd1aeb2fa109d122f1da420d0b0995442e77410a67a5f94180423902406a298e5e8ab5c7c06781554c4093e67b409724a902bb9890c865ea3e2317f0a44e2e64dfcc136871f9cd7aaa0832bcb05e3d70d62a904c27c308ca46b1a744478f6040485ea712c9593b09bec3cf83d4a2dae4f0f4128fff5be7068a2e3d881e6ea8501edab514fd05c8e5c147420b3f2024b4c1fb80597b37dad98498d98c64da31b5db64444f4eb98eac68ff898f7f949fabfe8fd9e67aad973b7842091b45cf4aa56ca96ce79404cffe97d31bb52302df5411d952962293b3d26ce3b8dfb0ba6b273ae4905ae93d495f478a7e54961c1de435ab8955f69c7ad30c1297882e64039fe0512b60dd388256fdbdeb8a57e4e4c94fd22ed34b8b3669ed3e9b107133b632a3de69e4e81dc498de8deccd25a7efa53a9b71888e3a9646ad290812b29d52b9ffec5c41295dae552bd4e1537963c80c13ebe0d309ee30227f3c257fa8faebb24bd690a84efd4d8f112ac898b7bf7c47cf009d96f73d29135894e09eb5c9fa2247cd8e7b27f963a81024f2470caf703c7a8e0f0968c96c0420f9a0054fc6e6c79ccc72e537ece5e6f5d95e051b8624ffb25a16c3c64ac62825eceb47da13fe7a4d6f8eaf5b490249ba87032f76d949eb0f5b6d8ed90bc211750f2c81b43e7bea09ec8211ed11289b967287be9d0e7a4d43df59c49c319978516d615a379584a8bde09afee82e156993645f7ea8bfafa95edb817e88300c0e7027034e9fafe25aee85642520cefd832a1a86b142440def62c2533583c8e519b8df6f6729c2bde6081c7acb2ce23d04e1ea480450af2912f888b6d5cdf6f8608019a9bef7a3ff7a3da6a33484d95c077b3c159d899713e7bd5da7abe1ddaf203e09cb79dab8f95ac33d5da06ed17815a312377895005a08c1bba5b95688cb606c7eabe68e23449b13225a8ef94ac8e67397c7d4c9a9483c650bd44e329307865d2e93ea150d36d3233a2ed2a99f29ffba06eb0cf8242d88274ddd5598d8139638f0ec12f394f1680cbf61e5dcce21d4269fb3dbd110ee3ade8c2eec89c6ac629cabafecb1f2cacc4272d4664dca1c6a1fb89fd74c80342d9ae17da6d7c427037a6e2164c69ab09dce6caf4c1ee7f4b37830a951f9a5d794d489df3a856c5b9b99f8b9198155767d3128a6f3ff458da3723a20c63a01aa78f134fb175131a3a1466c3e6f93ed38b004521aae3d2c40f172f3244ea346b28b0d7ecb4b4b638f4e4fad4dcb5e3b953cf7d4a1a84913046e7528d282769e9b5433bb1047d86a22911cdd09e4fb831fe41d72a4796f47acf9b98d173fdf800af5573474468e6d975a0bdfd174babe1aef2f3c2194b7ef78c4bc1472dffce263f1069fc65e9ec71ae9e0941ede083f60c5e0d54977d703b14e0bbac5af3f4e1cbbb010e65e0f237b0384f636081dd6bf6ac5706f41f741a6b54685c013986aa5c12c78c962e3003a1670f3d2177692987cc60c616df3afceabbaff82de9cd1831b9eccb311e34ec932396a72119472fedd1585402b5e611cc8e8a9e907758ea3fcc6b805496544e1286b357ec7b31adc3c20c570d3c049abfe4d045a53a052724d0be576faa88d3072745bf0f3dc945d8ddb2279eb429310403825a7240b393a3b34acf0548785d293f817d015b9ab0c3a6a0d3b7160f2b74c1af343234af4a541f456d008e206753a70014c8ce6709da4fd1bb40edaaa3d5be8629425a8da63b4c61470138621093759bd42800542b64a933209bed2ec0f86c3f40b71517ea1b1f99c7912495a7feab69111e289e7b801e37c58ddf4dafa7c0b272e810b2f2b098f9fac81ec1472860bf7e71b4921f7dfce6fb3bb80720a2ea5204883f01ace240b0a6a2abfa34444a25f6d662f4a792e68dcce1887dec2ab8314bdfd4bf6912e4b6c750805c1fe0d8e505a1ff41130daf9e5ce9beaea96de2221df2c8e44117a425f9a4199ac24daa6a2f187d666b965602df19b508c9cca909e2db188e5b1d2a61c25be2f5a6d2760b242d34b7037d69c8fb1605d98c62f92215967e5a34b1a32aa4e03ee74fcc8d327ea4d46a0fa666adcfc53682097f2e9236be9f2da6a7ff9ff82e62a0c6938631a5c891e019eff7c3c54960e7fc218b2b419fa785e2605744ad801cb41fa22cb3628ebd55ab86f2f53d61cd98a42a18d7a9a1aaf9f59cfd2ee7c0e982d151c507dc3ed1279b83252d11f38d6bb4a456543c93ca0293855fbc8e642d1f268b2465473caad4f50546a2c44be13180dae7ddbee7772994b7afdf94219054a54fb6ee7096456eb7732b77feec6a761836f70a87bc4f9ff8c8ac00a83d2514654dcb94eeb909f24a8d2935db04de6e0d95e8acb1e36c968872871d4d27d157895d9d2dff7ab6bed77193eb81113aaa7c671c12122035230402e3b58973a88d7bc7a2fd08ea7da53e434c905b643472e48f7d0b631bab30322eed01cfbdf0591fc8cc90c488a3d855b9e3a5e03145b3a6a81045d604dc103d849ab846705d6c2b85a4a68a71fe9254f729b282cb819b4c55691849000a53a0d6573c9596836fb87468d52e6e77782bf8e021acaa1af74b305944ebb9f2185c05d3bda1e3f4da3c6091b3b12a99f07194f002740acfb2c19549b79f6598f2f2be42104460053ba9270db12058d5c89ab4b3c01b08e403b5372748dacdb5f5d22b30a3c8a76f67d3e887d764f1d07ecae8735adeef7e425816de6ae315b1abc087230798322744a979a284ce3e2778cab40b09c75437f3b6aea947dc5460d43c85805e0af8ff421f8dfaaac78b775d50483ca71e9d000e3e1311e6df5737fc97b5b9a6897aaaa899da8b49824d175f471aa1ba141c679c1ae6013093b7944d9e399c2d7592ba6bb2d431eebc115bdcf4a1e1fe254a9ee5ec5014e3c343b1ab80797223205fd7b3ce6a0549e39216337bcad548502cc68876292af38332897459bc565028ddff1c79e101d6b2551042a30360d7428089dbd23d925d28f53abf3349f509114d2fd000e66e6d27d23c7af4763710b49d7dcc70517379ad87d13e0a4ec796ed4278954797b97cc884ab8e1ee1ea124fcc577d3ee4ff932786924cd9eca725431377ed591ea5f3ae7350e5e626b64ef2a5791d77e8a465f2b8891619c820e680265ab691ce8d45392d3dad8b28c50fed82215fb695fb46ceafe9aed1ec59fea48eb5fc2a619370b50134ebc7d465eb9984375656c807b2d0b2f872a34624fe3346141e97d7e97bc118816146b552af9d433ca96a7210f65e1c0b3e3bddeb5d1aac8ff38a3b7aa294cb679f959a0ade8b5eb2dcb2ffd2c11b0d010925059e7f2ce75ddbb174e91daec2605979249a1005f70b9d489fd051b1bc738849f4824f0bec67ff06865c8b8f5512b5da363a03f067b61973337218179fe258bf7f3dd6e381802ce9613a8817bf7a3b3073ef9fc7062e59e6cac4c1b041e957e72f4768f294fe297250c479b8d3d8c28eb5d35ff25de8fc1cfe80c9d01b0607d08066865e9633c645c6a4963bc9659086090d75f6807cbe2ccff132c247a203a26cc8ef821374635ba1d56486f9c40fb6074d0328b20fd1857364eaebdbbd740f7223aa2453af4fc5366574b2ba1d01e2fb1559e3f5ae47db7a5dabb020b5613314c35732090f12f0718317cd8defdf626ddfde7567d4f2ea8ed38515eae5815f20637f9736fab8ce46ef2be99d125cf125dd39e7d5b47b75990ef63b47b78457f6f50f33644af4995a048c6da9ed5eeabeaab7951bd0c21c3a519512ecc23a8e8e8805372e5b66b8eabdcddbdb9d91fccad55b4cfd14b4d08d82a864d67d648bf3a1e348409d87ac9e4d3e25703c66a55e64f42bb20153afc89d2c861729fbf1821e6075e084a88d43b0d3e0e679a742a77281a68229caa8a1cc7e2a00573ab6f236e8e4109a3c339df85bf69b0fd2f9ace26fc9a19a631bb95050ffdd078b00cf2352d983b98f32efd912e113f9d95dfb122cef7e6e14635da0305a5a5f87d91f1ad325051fbb1344e71a48b0ad0d26417c76c59381f73756ea2fa12abcf1d355428287b3704c8ba87633933540c0065ee887eb01abd10d86f8e7d46475108a9011443ee3248031e3678fbef98e4e6487895614b885839d315d79867f015fa6a949a997bf2dc944f64edd8177713c0a23889855418cac018ddb1ef3068ad08f5e802f2fed1f6d22eff3ce43da00d44bb9777d2798a7d64d06dfc614c15a880f55fb5608e223fb12a0eb455572b81918eecc42c5add564ff99c6295a5601b20d8fd7610deb2960b51040897f5443dfcede1e3d31c497a19c748f287c41a73678dbc0550479209d2077e878b86cf30ad19cf77caf040c64c380d58777750ff055507f6d9151976a8ad7615f01e862ee4bbb9de9031932ca88143d4f45ec847084257ece9f8b08496cdd47f217bb8585a038ec2b77384eea1c3b9022db060e1417aff14e951b586bbd5565b6139333ec4105b6f328fc63cb526c40ccf0774882417a678d090798fb515a2cc0ceb824cfa528c0d258b69bbca10cc39fbdd887bd6508b2325dbab954e02f503cd4f8ad9f35c47d0b208c5bf63229c4eb48a8cd129b91a46bf3471604c666eb896847f38eb5d88cda08ecb326e66c9ee6ccc9f53ddaec4f08d3d0c17077a97561dbe1671ab53afa13f5981304ff9bcdaf8da8cd4e2aa204f502c24ee91b4a2d8b97a857d8ffd3330a442953cced9ed1f21f3f45f7675207c9cb72a363f67de37bb212e943428169e35293b367c2555731d0fde40b23c6d1436d750c2cf5e5c83dce5942a159df15809577abfc4804d3be7b8631e26f9c115311e38397918cca219828e972c3159233f977126abb9691c3bfd4cd46391d2ec8a53d3831c369dc26354829d1ccb00bdda0d3e1bc3afc9186b10f64c0026aed3c6d42b8c718da2d374bf120b8aeddc7a9a8e49fa3e8a45b29a71fe96dbe22b9c85d4495bf6936e52796db308300c60bd1917994999bfc8f80efd139c325ba37356fd132944ff67e3b662b8c3a4dadcf711650df2e250b4e967f4765df9a72a964f61182ae56fe663121edc0be2642cd8a9e89b00c39e981feafa730a4640b9c9d631ce3d1d34891ceefac5517dbfba231de860e2c942a8950aa9b93d86fffdfefde8ef94508175e0cf2755da9aaff0b1998381e11fac2938e08c74526a3abd24f4fb785fecd5d61e8b683daf5fd2ee016f97b64532e219c427d08f56a572d0847fbcd87cef65785de4e719ce25efb22f68c3c403c1b304872398b8436c65890547fac9d1bf483cab649a07551d3780f5053e83ef5215e59e99476b8bb4fdefa94a371f19d1afcdaca0c9aac728521f1ccadec52c00ab1e7813f9dcb2b2660b0851d910e7664d2e594c539661137c642adf2bd702651e8c3b43ca40d018f5357b467988822e2f6fb20f7b6221234e70bc3dde466dd3de5aa7980ea9cde1108c32beaba649befa4a08b9dd13216a1c95696c33b60a84027e10f7c7ed60f0e0bcd54b0b2170a88f37c7da427e93612c5ca24e929918857649b487a41fb26721352ee832a24a0d6aaa3105ab48454627a865b3dc65450ab737c6eda23107b6df06427e1ffcaf8674768c7ffe7ad47960267452045db648880f2eeb1de065e0704566ad93400b48c4ba8fd175fd862d6989d78e8135eb19aa08b428aae3ce9e5e8e99b220116d45b83531c9e3d4bcac601b31aa4e8725b75c0abf6958cff107ab608e6e0f5c273b18ca98afec2555b5ddf6f6a5d03a930086b0eb942515233e9dc05f827abfbfc3976bfeb3d5ed6849d7184d3c57a3984b8fcae35378fbad65aee5f450af95218699f7248534bcbf960a8cd756662323fd25740c7b1d419bafa276b3b18d52faf5360bb6ad0d50940271a2247bf16cd616ff584fc490728835dbd3f0d1758c9aae0174909d06420074b044ad0f47aac1df5b4f6746d0de473878250c2797d21a80a098a48c6d3e62e7f13202d71864ba6bc235e710a649f33340100a3723b9004125560193307e24e861502ae06a5cd33d1cf9e831ff9d20c8f5ed55134a6238122d053747f455c39a8c2de80f4835f5ff76de61f1ae0388ef4bc4469fcaf78ba97462bebe00d2c126fc3e6aab591eb3b566ab82273a410607b049b3b5acc924d34355220d1c06c1d46b0577319cf6623462c920f940efb5b6c5b15b5b1f119245cf90f74159a176a6fd67e1d65008379ff5c2f1';
                const message = '56454c9621c549cd05c112de496ba32f';

                const sigBin = window.ToUint8Vector(window.hexToBytes(sig));
                const messageBin = window.ToUint8Vector(window.hexToBytes(message));
                const pk = window.ToUint8Vector(window.hexToBytes(xmss_basic_object.getPK()));

                return window.libqrl.XmssBasic.verify(messageBin, sigBin, pk, 4);
            });

            expect(verification).toBe(true);
        });
    });
});
