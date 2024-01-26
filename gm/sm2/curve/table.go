package curve

import (
    "sync"
    "strconv"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

var precomputed = [2 * 30]string{
    "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7", "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
    "95afbd1155c1da54ba220b99df9f9a14673891d791caa486e18bd546b5824517", "e8a6d82c517388c22eee750f4053017cc3c7d1898a53f20d8e4450eb334acdcb",
    "82a0f5407d123db6cb129aa494da9ad4137f6c6149feef6ef81c8da9b99fba55", "f12fa4696a22ca3fecacab94e973f9c3a961b58f0cf58373fdeca00772c4dbc9",
    "b692e5b574d55da93db7b24888c21f3a2b2308f6484e1b38eae3d9a9d13a42ed", "a175051b0f3fb6135a924f85544926f9db61ac1773438e6dd186469de295e5ab",
    "c0023fe7ff2b68bd8fe75e5a128a56a7e3d6467deaf48fd7a72d084f62c8d58b", "796c910ee7f4ccdb5d1ed6fa89cbbadeb52b6d9b19a69cd264f67782316815f9",
    "75a34b243705f2600e8cc24c3f546142daaba91b5d952c9b1b2150c1c5f13015", "642ce3bd3535e74d4683df176eeb2444636644aa0c3a062377d195421cef1339",
    "d9eb397b441e9cd03622a87fb284554faf2b71164f191d634a59ac2c6e7ecc08", "f3f000bc66f98108afa87501eedfc9f426fb89a40b4a663aa66b8a4893b6a54d",
    "793fae7af016424544c0757f3bb8b60016888d8ee4003187ad8bc68ce031d616", "e03d7a8d19b3219a65c5b129f5f7ad5d08666ff52dbd25f9210cd042973f333b",
    "1b200af30810b682d9f46b2714a071ee261014f7d3445dc7d68bfbace0e00392", "248b7af0b05bfad2d822913cf0d2b82d74a08f17bf8cd9810d91d8b12ae69bcd",
    "8e74ad0f4f957cb1d269f3564eb5d180f278e8a34df05ae5ba119a049e62f2e2", "55a5ccc7af3b6db4f43eab474992904c91373f20630fdb7f112ff4dabd76e2dd",
    "4c55fb20426491bf390542a0ba95c174f5a9e515eb71c2c15ad104a8bdd23de9", "08f89a03b8fdebeafd48731b7a8a8521d2ed977f88f0963591525735ef626289",
    "f9def2a46dba26a3d81ea23b7738c17c1bb2700db98a762c7e8e61ea35eb8e2e", "91692899d5ff051356c22652614283bb34664a0896ccde0e183a7912d05e329f",
    "da72c379dae3ca8baef159463f8bfb25ab95de03cc8510cb449d48d8f3bdbe19", "b170d0da75ed450f36ba2752538e348c4e524bac38a58020cba9315ce82cc3ea",
    "a5d9873b3fb2ddc75ba79a0c705853a07eda17d917827976947af0f52b4f8da6", "e2e23f0229a84a35f60c8ef6633be6a980ee8ae526f25f02c2a48162a5fd9ce9",
    "d94eb728273b3ac77c1db58b7b86eb33237eb711eba46feebc4945bd86bb6afb", "be3c1e7ac3ac9d3c19b32eb5afc2fb174a6067cc45f70212be1717e59568d0a4",
    "3d251b54e10d581f71e834cf86896c1051e46707fd55865668a88405ae53c1e9", "87891d33fb98b4d85931f6831a8d8c11eeaf729853e526fe1884d5b0eeb19032",
    "ef14b338007777910a6230c81642e71af5df5d83bfb586599047673fcac14893", "c9bc50d02e2b960a36fe159b6dcd01bb7ace937791313d53cf1e99afa3386fca",
    "bcb7de0f8f70520eca235ccb4144dd05bbf9bb2c62dd5a00716e5a7ee12e162d", "93d90f776b58c35de9076332afc6a10d53c7102ea04de08d981e8964947cb8eb",
    "eb5ca335326afad3aaefc62be30a298bc607e811fef0785a834dbff6678337ee", "edcc0c2aaa2d53ce1346c82d66f6c642ca4b6ef5785388b49774fe1384af54a8",
    "1a8526428e1aeae7fc2fc8670741392047e4018c736fb3d0b896b3f764b9e6f4", "63b0e9c7141de1b02c4cc396dd43b0117474dedc995384d01386802650e2ae60",
    "913614c66a91a647dfc4c81ce36739121fe07b18933ed257eb5fb3b369d17771", "cef0791a6e6ce0bb8532307e7e4ee08c03109c2deceff09118aee853c0ba877f",
    "e0997d4759d3629851e8fdd6283187c2bbf7f8b49f125aa9f0e9f5d8057a4a0f", "fb57404312680f44152d01e23859f5e23ea275dbc860722f67ec3c5c6f4221c3",
    "5159d218ba04a8d99151aa584775c85711006e9fc51d112f21ac3df849be2a1f", "4abbd1ae27e13f118eb91ec1569c05a98f4753cafc2ad9d898b7d1a925fd1866",
    "92ff3cc3c1c941b6f927a40110f02017251cd7140e540758616f6644b2c11f4c", "dc84ce34b14bb7cfea9a9d1ec402e6c24633e3ddeb9dbd4e3249906213f565fe",
    "9cac08f200234bc034f6538a9e90cb4152dcb0a79b63efcea93e23e5436ff69a", "a296f5577fc91a93589d74610ae6bd2707d4d06de036be576661825b5174a02d",
    "d6916f3bc16aa378921d318c3d86785c8b0f6b8bb5bcd34010acefa9d29721d0", "ae9da2272daaced35765e27626479e417b93256c2fe7e97a2a0d646a7ad84a0e",
    "807ce6bea24741aa1eb96792aba6b832ebcb4ff2da3877d356fdc215f7f34ac5", "aff6d783d56c92867639ae749af2d303d187d4bc796353a7ff1c10109c721fb4",
    "faf2cb8c87fce11971776611e00d2528cba3ab0099a836a56002d51b6290dd01", "11ad7c4b8597f6b6837b6335a2eb2453cbbfade17cbce919d445228bdf6882ae",
    "e55f203b4b8d9672def1a9a6c505323f7ae3d25630a7427748de8f368cf2e399", "687d41364d5fef53d60bd087d47cbdd8e160e6d4b2737a76c58d8f0d9a1e6e97",
    "8f13cc8d06dd7867ff383d1845b64e4f4c2a9d120b4ba5ab83f21bbe056bbf9b", "53b49e6cc93fb5a867d14dee6c1e75a3fd2546eae7cbe44bf3a292d8424f0995",
}

type lookupTable struct {
    points [16]PointJacobian
}

func (v *lookupTable) Init(p *PointJacobian) {
    var p2 Point
    var z field.Element

    z.One()

    points := &v.points

    // We precompute 0,1,2,... times {x,y}.
    points[1].Set(&PointJacobian{
        x: p.x,
        y: p.y,
        z: z,
    })

    for i := 2; i < 8; i += 2 {
        points[i].Double(&points[i/2])
        points[i+1].AddMixed(&points[i], p2.FromJacobian(p))
    }
}

// index must be in [0, 15].
// Select sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func (v *lookupTable) SelectInto(dest *PointJacobian, index uint32) {
    if index >= 16 {
        panic("cryptobin/sm2: out-of-bounds: " + strconv.Itoa(int(index)))
    }

    dest.Zero()

    // The implicit value at index 0 is all zero. We don't need to perform that
    // iteration of the loop because we already set out_* to zero.
    for i := uint32(1); i < 16; i++ {
        mask := i ^ index
        mask |= mask >> 2
        mask |= mask >> 1
        mask &= 1
        mask--

        dest.Select(&v.points[i], dest, int(mask))
    }
}

// point init tables
type pointTable struct {
    points [16]Point
}

// init
func (v *pointTable) Init(table []string) {
    var x, y []byte

    points := &v.points

    // The implicit value at index 0 is all zero. We don't need to perform that
    // iteration of the loop because we already set out_* to zero.
    for i := uint32(1); i < 16; i++ {
        x, _ = hex.DecodeString(table[0])
        y, _ = hex.DecodeString(table[1])

        table = table[2:]

        points[i].x.SetBytes(x)
        points[i].y.SetBytes(y)
    }
}

// index must be in [0, 15].
// Select sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func (v *pointTable) SelectInto(dest *Point, index uint32) {
    if index >= 16 {
        panic("cryptobin/sm2: out-of-bounds: " + strconv.Itoa(int(index)))
    }

    dest.Zero()

    // The implicit value at index 0 is all zero. We don't need to perform that
    // iteration of the loop because we already set out_* to zero.
    for i := uint32(1); i < 16; i++ {
        mask := i ^ index
        mask |= mask >> 2
        mask |= mask >> 1
        mask &= 1
        mask--

        dest.Select(&v.points[i], dest, int(mask))
    }
}

var baseTable [2]pointTable
var pointOnce sync.Once

func pointPrecomp(table int) *pointTable {
    pointOnce.Do(func() {
        baseTable[0].Init(precomputed[ 0:])
        baseTable[1].Init(precomputed[30:])
    })

    return &baseTable[table]
}
