package bencode

// 多文件 包含5:files
// 版本为通用类，非通用类需要直接用 map 获取数据或者生成数据
type MultipleTorrent struct {
    // `bencode:""`
    // tracker服务器的URL 字符串
    Announce     string          `bencode:"announce"`
    // 备用tracker服务器列表 列表
    // 发现 announce-list 后面跟了两个l(ll) announce-listll
    AnnounceList [][]string      `bencode:"announce-list,omitempty"`
    // 种子的创建时间 整数
    CreatDate    int64           `bencode:"creation date"`
    // 备注 字符串
    Comment      string          `bencode:"comment"`
    // 创建者 字符串
    CreatedBy    string          `bencode:"created by"`
    // 详情
    Info         MultipleInfo    `bencode:"info"`
    // 包含一系列ip和相应端口的列表，是用于连接DHT初始node
    Nodes        [][]any         `bencode:"nodes,omitempty"`
    // 文件的默认编码
    Encoding     string          `bencode:"encoding,omitempty"`
    // 备注的utf-8编码
    CommentUtf8  string          `bencode:"comment.utf-8,omitempty"`
}

// 多文件信息
type MultipleInfo struct {
    // 每个块的20个字节的SHA1 Hash的值(二进制格式)
    Pieces      string             `bencode:"pieces"`
    // 每个块的大小，单位字节 整数
    PieceLength int                `bencode:"piece length"`
    // 文件长度 整数
    Length      int                `bencode:"length,omitempty"`

    // 目录名 字符串
    Name        string             `bencode:"name"`
    // 目录名编码
    NameUtf8    string             `bencode:"name.utf-8,omitempty"`

    // 文件信息
    Files       []MultipleInfoFile `bencode:"files"`
}

// 文件信息
type MultipleInfoFile struct {
    // 文件长度 单位字节 整数
    Length   int      `bencode:"length"`
    // 文件的路径和名字 列表
    Path     []string `bencode:"path"`
    // path.utf-8：文件名的UTF-8编码
    PathUtf8 string   `bencode:"path.utf-8,omitempty"`
}
