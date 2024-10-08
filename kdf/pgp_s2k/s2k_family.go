package pgp_s2k

import (
    "time"
    "hash"
)

func tune(h hash.Hash, keylen int, msec time.Duration, _ int, tune_time time.Duration) int {
    var buf_size int = 1024
    var buffer = make([]byte, buf_size)
    var time_used uint64 = 0
    var event_count uint64 = 0

    td := time.Duration(buf_size)

    timer := time.NewTimer(td)
    for {
        select {
            case <-timer.C:
                event_count++
                time_used = time_used + uint64(td)

                h.Write(buffer)

                if time.Duration(time_used) < tune_time {
                    timer.Reset(td)
                }
        }
    }

    var hash_bytes_per_second uint64
    if td.Seconds() > 0 {
        hash_bytes_per_second = (uint64(buf_size) * event_count) / uint64(td.Seconds())
    } else {
        hash_bytes_per_second = 0
    }

    desired_nsec := uint64(msec.Nanoseconds())

    hash_size := h.Size()

    var blocks_required int
    if keylen <= hash_size {
        blocks_required = 1
    } else {
        blocks_required = (keylen + hash_size - 1) / hash_size
    }

    bytes_to_be_hashed := (hash_bytes_per_second * (desired_nsec / 1000000000)) / uint64(blocks_required)
    iterations := roundIterations(uint32(bytes_to_be_hashed))

    return int(iterations)
}
