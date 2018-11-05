package kube

import (
	"archive/tar"
	"bytes"
)

func WrapAsTar(fileNameOnTar string, fileContent []byte) ([]byte, error) {
	// Create and add some files to the archive.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	hdr := &tar.Header{
		Name: fileNameOnTar,
		Mode: 0755,
		Size: int64(len(fileContent)),
	}

	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}

	if _, err := tw.Write(fileContent); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
