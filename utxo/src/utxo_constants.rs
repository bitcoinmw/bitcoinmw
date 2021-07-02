// Copyright 2021 The BitcoinMW Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub const TESTNET_SHA256_HASH: &str =
	"026b3d712ea6af41786d4c7fca8047f2170c8e48555d71e8b88c588f858e96ee";

pub const TESTNET_INDEX_HASHES: [&str; 56] = [
	"5e560bea1a5baf3b1b53717fc17522374194695b51c925e9f61012eb8e8eb558",
	"072d2d6db3bbe962fd589524b5caefe05fe1a4686e8d3d4e04c1da5e7558fc8c",
	"1869d4ca52fcc3d6667f67486e5033b3833bf4464136f7bb958512e5adbf0da4",
	"76abbbc0ea1e5526b938d2a8aad28faff2210979439b925886d778b3aded8f35",
	"c5eb068203214262582987db6a1035aee6880b9a95f87bd9837a61a3d415abe0",
	"21d47a8abad8befd5151f01db7215f85c53b9d23e51f303ad1a90266abed2b32",
	"26794122fe9d308fd22fce176307161f32906ab289f1bf10a89bd56b89cc49e1",
	"ef910f404b877025fd79518005d1678babd7e92dd8698a7800359aa6ccef2fc3",
	"c2536a933c1d8aae83a19244a05db9ab88252a4b6c18be0d064cb0fcd97541b2",
	"800d86e1f6e00b1caf9bce5a991bbf600332e1222630c4ec1ce7bf453a58cef1",
	"459b58c44847f1ac6a654c3373ea972f70a4daf7f7631fe50dea4c228a572124",
	"a0f35726e87d7f33cc011baac8ffa58df115b667ccae7e16de508807ffca3c3d",
	"87b77f1ec015ddd530bb8c800732f705b2d77de4726f400918b7007b36de54a0",
	"e870b0bdaf29f6d0f7d31098c31c82600128b24045c657ea9a7c56b3c0b97892",
	"05f08ec0068e88d7a11e9700c2d3638df3a41f111eaac4b56ba7eb2fe21f28cf",
	"12d42a141a5c1ca0d1744a20a2972a0f3c93206a07bc94853004346add9c8677",
	"5066d882b840f8f419443d672cb6c6ec990bff1fbeda7df1c25d79969f195990",
	"303fb2bf2d943d484a1ce27ff2add22cf4765ae99d822e6c0caff79af3e8a507",
	"0eb7091b9536ae626a495d935555da5f964205ba7f58fb8d10ca7215669ca968",
	"7986ee24d55b76a7b2bb9fb4409fb927860f6177ca238901cba2991f41fab46b",
	"30ceb7d9e6c758339dd074d11171d8829d8fe7f41150b156df13f5fe44f328ef",
	"5110adf0425c93f16f58efe71a0d56630d2d019b2f4955a28979f6e320d43e40",
	"c4d807665d561090dfd507367fc51893436cc4a5f466a8da51ff4cbfde35588f",
	"c464ca097db2c9fb294b2784df58b401d98ccc9a637d0cdbba7de284ef7fe20c",
	"1dbbed765d019bd202f7ba5f457877def820795612567a0427c639a29e2a35ff",
	"780a7c5500dff84cf6dbbc5a346ccba7190c36bece936f808f39412c37b3d008",
	"bc05d2dde3b1b81aaf99af374cef3648e250241f12e1bfee1b7d78e5378f2886",
	"6fb555da3ec6fea6acdbd24af3bbb65261b61e6c3a47e8e298ab5216f0a2dd53",
	"53abcdff4bddb1ddbc9e4c5a7e6e2ec36ba7e0f467d20f89cd1c11075d426fe7",
	"5371d37cd1e818d56a4e68b12edb999e16addc590d485c9015a6500d92539b0c",
	"9c0f96ce701be673bb62a138278dec130bc9dcdc0d887db5cbc3893afe6f6d46",
	"d9869142108f821c0d0b31bd173c2823c81f2bea3e2f9ba751742054383013e4",
	"10fca3838eb4afa5248fb021dfedb52def622cda4e913a7c5b4cc0b32b0e2093",
	"a6a4585150860e338f63a68bcf9a76c17f2acd7ad782ffce9a3d8b6f9bc152ce",
	"70fdca93d65c68380bbf99de3171f8ebb9b6a2dd0a38dc63ce7c8b72d9650fdd",
	"5dba4118dbe38e05ddb8f7ac708cbbf7ac9a764e9b0ccb631809979f094422d6",
	"13bfcc43573140ce47fa9b4363c738e2926a9efee313f3580f3e0dc0782f5e1e",
	"d5432fdec3e1cacf052a9fdbf5dfff99901abc63040147cfce3aac2cd2e279b5",
	"87c2c5285b1f3ca240e45dbfd86c79775b0d31e797f16c8a05057c480c5917c9",
	"c2ef09070ae72438d8fef5b1f9af72862bc032902e617cc28b7bdb4831eaa195",
	"2a8ab819d7b15c86e73a4fe95c02e84134a82587c18274e7d86b0b62e0fb3f25",
	"1a1c7ae45298f83207f3122263801e125450528b6095bd50541c2f237dd8901c",
	"b07ce8b35fdf3dda16c4846216530f0b1fdc3021eac030609e5c65e19d1904db",
	"bac545b1a908eeff9dc4296ffd4530dcd3f0e4bd9b327ff7f75c1b907c5b9afb",
	"e8050873d029d7beabd713f4f5eff5d99be1f2b5cdcf033bb9e2a1647519c78b",
	"e88eac10830d493bc03791f89f18958cdc7f151780ff04e0318491aa1f2e6e3b",
	"9be4c47560e2819f5ae090ce1c4dfe26dfabe8938ceceb195d8aba8b855e5cab",
	"a6e92c639f7d463c86a58925b1b2fc12553ef51c43413a212e73274cf7333586",
	"8befeb3f2600fcdfaafd207f11dadcf3b268b6184ab9b6a93cd9d6ba3ec8cacd",
	"7f3db8107da52c1ec07eba425a619826695687725a81ac82ed2961cb66729784",
	"2b893c481eb1b75978abed2c90b79d4c504a061cef55b76a5b1c7898f0599621",
	"d9ba2c0f9b17d9b6b3edb8f10b2cdc7c276e9ba0188bd88a1ceb982bd2b459a3",
	"b4e87f7cfb2cf5b2cacc08fcb58c0c8fc7f154df494cea45eee39c271d9c7b52",
	"fcda1a97d45af12f68b21c91387ebbad0d08a27bb9450e91cd62bc24d51f1999",
	"28c118fd353a304ff52e5d88e24dc3f92591a4a3ddc3ddb60e38c60cabb92461",
	"ee9bffd9b5a7b6cf6df03167e64a7ab193fd6cbd4c052f745ae4212025f66850",
];

pub const TESTNET_DATA_SIZE: usize = 935221712;

pub const CHUNK_SIZE: u32 = 512 * 1024;
pub const INDEX_SIZE: u32 = 16 * 1024 * 1024;
pub const PARTS_PER_INDEX: u32 = INDEX_SIZE / CHUNK_SIZE;