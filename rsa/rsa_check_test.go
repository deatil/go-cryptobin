package rsa

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func get_private_key() *PrivateKey {
	n, _ := new(big.Int).SetString("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)
	e, _ := new(big.Int).SetString("010001", 16)
	d, _ := new(big.Int).SetString("63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9", 16)
	p, _ := new(big.Int).SetString("cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b", 16)
	q, _ := new(big.Int).SetString("c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5", 16)

	prikey := PrivateKey{
		PublicKey: PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}

	prikey.Precompute()

	return &prikey
}

func toHex(bytes []byte) string {
	str := hex.EncodeToString(bytes)

	return str
}

func fromHex(str string) []byte {
	bytes, _ := hex.DecodeString(str)

	return bytes
}

func assertEq(t *testing.T, a, b string) {
	if a != b {
		t.Errorf("assert got %s, want %s \n", b, a)
	}
}

func Test_private_key_precompute(t *testing.T) {
	n, _ := new(big.Int).SetString("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)
	e, _ := new(big.Int).SetString("010001", 16)
	d, _ := new(big.Int).SetString("63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9", 16)
	p, _ := new(big.Int).SetString("cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b", 16)
	q, _ := new(big.Int).SetString("c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5", 16)
	c1, _ := new(big.Int).SetString("c4c5b893ac7215a18383cba6b27bb4e0f8a7890647da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5", 16)
	c2, _ := new(big.Int).SetString("c4c5b893ac7215a18383cba6b27bb4e0f8a7890647da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f8", 16)

	prikey := PrivateKey{
		PublicKey: PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q, c1, c2},
	}

	prikey.Precompute()

	if 256 != prikey.Size() {
		t.Error("size error")
	}

	dp := "8a869c63005453c791aca20e62ab42b8ec2501f312f3c81e9e9cb28ef48fe5eaa3403e9db4c37054cc69390335fb9376b7de2cdf0a87cff25d7e54ab733bbaff8f34b4076fc8914f7e66149b04a82d123fe5eefcff6e78f0bfef4c8ded5f55fa5c2a62b6e67231b8918bdf9723778c51417be3ea2e5c546c49a2ebf241fab4cd"
	dq := "6fcd7c1b840eea5573f94d9c30ab7351a456e4d74adcf6ac8b8b1bf82e5c20d7db19015857a7286a691f2661bbb508ef84e8422d581383d067a6edc5b019e56e974e8e02b06cd0ab230f794bde5e97e59ef677ff77252f2d1d5ae58610a541209de13d75666fbe692863abb0db01cc635fa67e591663b26fefe5ef326e8bb685"
	q_inv := "a3025ed7af8f1b9536f34fa9cd0f6e647b61bf31017926070b77565b5f2572d9c83003e307749f78a90e5b3bf15df64371ec82308ddf3a39c35501c816fb01ab21632152d71652cb43e2796b47dd29de4511371ec56e760f9d35c14e5e836db3b492866fc401ee59d0e8d64121a55695fc2ef495861c0ca2d42ff54ca622bcb0"

	assertEq(t, dp, toHex(prikey.Precomputed.Dp.Bytes()))
	assertEq(t, dq, toHex(prikey.Precomputed.Dq.Bytes()))
	assertEq(t, q_inv, toHex(prikey.Precomputed.Qinv.Bytes()))

	if 2 != len(prikey.Precomputed.CRTValues) {
		t.Error("crt_values len error")
	}

	exp := "72947fe11cb8f4d7a3a6693b74cd27747e00221eaa2413e44340e7c1906ce71367e644be9e2d7bc9d9aa25da168a4ce7b7ad3cf45d39abbab55571da1d11634a2c645fa6038b61822b037a02e76bcdbfc8c497b47b863b485b270b46c520262204e8f000873e95efee8a9235b7a628feef36feb93adba8d882f0a0060ee95b19"
	coeff := "24866ea0c2869d06893e642a5f1f39a5b4cb050bd69dae13387bb7c2aa56344fc527708de0cad92eaa2e22f5f1c2fc7049e2d3cfa65dabea73c9fc2dac9fb2e3d72bff9030b2ae0b0cc7664478a9adb3bf05b106f9c586dbdd996006a15a58e69950c17f264d43984bf1c62f988554dcfaf736e53db4f921779dca67c95eabd6"
	r := "9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767"

	crt_values1 := prikey.Precomputed.CRTValues[0]
	assertEq(t, exp, toHex(crt_values1.Exp.Bytes()))
	assertEq(t, coeff, toHex(crt_values1.Coeff.Bytes()))
	assertEq(t, r, toHex(crt_values1.R.Bytes()))

	exp2 := "7680dbd54fc851285c0ee3834e88a4e37865d19a3d82ac12f9338147c190b6af4ccb3b8f72cdbb93f3adeb8af464ed7bb1638bd4349dc96dc4295d164287608b0870fae8308b7cb6c22109cc60dcbb31be76ce23ac22e4a44f9eacab6c3f83cfdee50a980f9ee8094e5e43336305191494fd029ee1774c7a47b6b7ed3656bcef"
	coeff2 := "5512624023ed5ef4f7b4a4f2c159a73075a6e45cf56dabfe654b7e65b7c701e1a9119d7a0fd285f79072f838be82285c7076802ff5f1817ae1a1905d0920c48905db7e4212d51745ce775b48558adea4e1a13cd41aba042a8af3942e3265e93ccb72ec55074d75afa30cadf5ddedf74c57d38254e813895af3b0f82f2f699f3b"
	r2 := "78b90768b98df340623395bbdaaacf866f405b94e51b8a53f1586d576ef603bd97bb07ca8e439ffbf9b2276acce1985c12224f7b31041b880fc0a9fe0ddb076feb0139056cd82af5a5c5eb13630976f94486d5e0c51021ba4ecfddf58d972911164659610639bb0ad1c7acd138802ca1fbd0ecd3f8892bdaddf4efb2735f19d4b3903ed1767ba94e719e46b9794a484f16386e76bfb9802a28bc63e6dd1ed6c60f86c993d10a81e9fbcc7631501e32a0348049000b76d176b8efc250b3bb2828ec5adcd92fec125837a9c30811aa7cadc57eeacc51c82e67d4ea1d45efd97aaed198c23c123fd2ec067c98fafa034c3fd1eb1f879fc1bc06c26c1dbf110d18593afc32238db74f01f6e66d132517bff2178f14ff58ffe54bab1e020e99efe61c48f06ac1583cbc5cd1a8e95a817319f785d290674ddba2c57cd1c58c36192f8dfdc2e3ee94171fc494176d1a0de940c235ea4c3ae5dfaaad838591016088c666e82a5e88a4b65a75cb01e96a176b70054e40531653499371fa228dff6f5cf693"

	crt_values2 := prikey.Precomputed.CRTValues[1]
	assertEq(t, exp2, toHex(crt_values2.Exp.Bytes()))
	assertEq(t, coeff2, toHex(crt_values2.Coeff.Bytes()))
	assertEq(t, r2, toHex(crt_values2.R.Bytes()))

}

func Test_mgf1_xor(t *testing.T) {
	out := make([]byte, 25)
	seed := []byte("12345678")
	h := sha1.New()
	mgf1XOR(out, h, seed)

	out2 := "651b52269d52682b1dca3f14e1b56b5a7cf7bba576cd6363a3"
	assertEq(t, out2, toHex(out))
}

func Test_DecryptOAEP(t *testing.T) {
	h := sha1.New()
	prikey := get_private_key()

	ct := "877611149e10ea45cb80b5497a8466c99cbff0ecdaf8b56d9566e3d96335d5f5913f2b627c9857eb39b96ce2e0811ef22e617f8010fcd4a7e84efaad6c6be1a14cda0fb75287a2b8439236e9cf2addf4ef0d4e2813e506adf767badbed42c3bdeb5d493f5b6954018cce4923d6a2e1701bb45eb9b247cecfe37a8a3c5694abd990b5b7ad6d4e0b6d35dbb2565ab10303fb430848ab153be882faa0f972e8a0dbb1aa2061d87769210f528b89bd0d22823982255241d86fed085b7b5d6e1b01ee2ee699058710086d55f079071f0cad5f61caf3be4ff0de8036964b7f3642c05af996fbd673c6e79c90158a0ab7f517f83988f3062d54790a2446927bd6269034"
	ciphertext := fromHex(ct)
	label := []byte("label-test")

	out, err := DecryptOAEP(h, nil, prikey, ciphertext, label)
	if err != nil {
		t.Fatal(err)
	}

	msg := "12345678abcde"
	assertEq(t, msg, string(out))
}

func Test_DecryptPKCS1v15(t *testing.T) {
	prikey := get_private_key()

	ct := "24cb659f249d437efb94652b840e09c7124a1d9db2737d38979ac534cb038fd01c35fb1619fec7eaa2424c0c90f2827dc45ea925f9cd79607e4270895ef9f8142055ad2009fe273626c481df5835c96e0c4838b7bda3e45336b381434cbec1acd5f4480d61a08c2c304e773c03b8171c2c6f0aae8e07a8f600c688e6126ca69a99a9166cfa67ec61791b84f1966892ab3ff6f853d7482a83c7b25a35a4837f370d3f9fa6b523cd3734299ab5b400d2b2d15b20747f4384acd4749334e14835f691e5f4e3ca41cfdf269f486818f53f7a874ad7b366fdb23dbc840a8ebc504a1488280dfb1041ff461825b6da794d60efc8844312030c590cf414fa1c93008115"
	ciphertext := fromHex(ct)

	out, err := DecryptPKCS1v15(nil, prikey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	msg := "12345678abcde"
	assertEq(t, msg, string(out))
}

func Test_VerifyPKCS1v15(t *testing.T) {
	prikey := get_private_key()
	pubkey := &prikey.PublicKey

	sig := "6964777343044b22954de38537a475b76323f5358e6f99730fcb42ba70da53979712eeb446afb63ef68896a8f565e2e4414807f6540ad013a4e2d6f3fa76b5eb1f36cd4b299e4e07763b1f1c3fb420d47d60fe42114c5f2f30249fd5dce681499787f43c52f811eded39619d73666db22b95de75b06925f948ef413e29fe04d55a4c5558259fba1b0a7439490fa2deb095592d860cb0f41d334933fcb6c7f480a4889ec2571faa8788393946710c6d67272e52e746cdb08ff92855f2684ed1c19b074ff68f56e1ab5890c9bb6178b850c806d1fb208d41d97ebff00d785e91bffaab4d9b42ef175000673d89c88356af08d40cd3ad83a37abd0a9d4ae1ec4ab9"
	signed := fromHex(sig)

	msg := "12345678abcde"

	h := crypto.SHA256.New()
	h.Write([]byte(msg))
	hashed := h.Sum(nil)

	err := VerifyPKCS1v15(pubkey, HasherSha256, hashed, signed)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_VerifyPSS(t *testing.T) {
	prikey := get_private_key()
	pubkey := &prikey.PublicKey

	sig := "794ed1f1eb627dcc8115590771f40047d9a64858182c583abe8431329f53380a128711d93eb087c4fbf349015b34fa5c19aab0a0014b6b357d30ede2b3948047f5b448c7180c7fd4407e1aef4b8edd419369c2d63448c4c7acbee018a697bd398e202f916cc249b935f738cc3d744c1609a6aaf4ee2448cce647e37d5175ec298eb28ae415b0c5fd1f22fe866256f6b14a762de0b34b702e9a6aed04672ce355d4598622e6c89c1bd3beae7ef71e83c7814048f100d6c377c4b97086b9a9ca6b25c59c40240b1b1696760022868ee34f3f75a7a95d5abcdd4e6ae58e7912f46545186838320d4f96d7ed03e9a88939b57ec6ced1649b9293c65eaa84bdf9ded9"
	signed := fromHex(sig)

	msg := "12345678abcde"

	h := crypto.SHA256.New()
	h.Write([]byte(msg))
	hashed := h.Sum(nil)

	err := VerifyPSS(pubkey, crypto.SHA256, hashed, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMgf1XORCheck(t *testing.T) {
	{
		msg := []byte("asdf")
		out := make([]byte, 32*2+1)

		mgf1XOR(out[:31], sha256.New(), msg)

		check := "ed1b846bb9263900c81782ad08eb1701fa8c7221c6576377317f5ce809899f"

		cryptobin_test.Equal(t, check, toHex(out[:31]))
	}

	{
		msg := []byte("asdf")
		out := make([]byte, 32*2+1)

		mgf1XOR(out, sha256.New(), msg)

		check := "ed1b846bb9263900c81782ad08eb1701fa8c7221c6576377317f5ce809899f5a22f280d52808f493837600de09e4ec924a2c7cef0df77bbe8f7f12cb8f33a665ab"

		cryptobin_test.Equal(t, check, toHex(out))
	}
}
