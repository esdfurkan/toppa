package netstack

import "io"

// bytesReader is the io.Reader adapter used when feeding packet bytes into a
// buffer.Buffer (gVisor's Buffer has no plain []byte writer).
type byteSliceReader struct {
	data []byte
	pos  int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func bytesReader(data []byte) io.Reader { return &byteSliceReader{data: data} }
