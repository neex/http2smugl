package main

import (
	"encoding/csv"
	"os"
	"sync"
)

type CSVLogWriter struct {
	m sync.Mutex

	headerWritten bool
	f             *os.File
	w             *csv.Writer
}

func NewCSVLogWriter(filename string) (*CSVLogWriter, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)
	return &CSVLogWriter{
		f: f,
		w: w,
	}, nil
}

func (w *CSVLogWriter) Log(d *DetectParams, result DetectResult) error {
	w.m.Lock()
	defer w.m.Unlock()

	if !w.headerWritten {
		if err := w.w.Write([]string{
			"target",
			"http_method",
			"detect_method",
			"padding_method",
			"smuggling_method",
			"smuggling_variant",
			"result",
		}); err != nil {
			return err
		}
		w.headerWritten = true
	}
	if err := w.w.Write([]string{
		d.Target,
		d.RequestMethod,
		d.DetectMethod.String(),
		d.PaddingMethod.String(),
		d.SmugglingMethod.String(),
		d.SmugglingVariant.String(),
		result.String(),
	}); err != nil {
		return err
	}

	return nil
}

func (w *CSVLogWriter) Close() error {
	w.m.Lock()
	defer w.m.Unlock()

	w.w.Flush()
	if err := w.w.Error(); err != nil {
		return err
	}
	if err := w.f.Close(); err != nil {
		return err
	}
	return nil
}
