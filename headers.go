package main

type Header struct{ Name, Value string }
type Headers []Header

func (hs Headers) Get(name string) (value string, ok bool) {
	for i := range hs {
		if hs[i].Name == name {
			return hs[i].Value, true
		}
	}
	return "", false
}

func (hs Headers) Copy() Headers {
	return append(Headers(nil), hs...)
}

func (hs Headers) Combine(other Headers) Headers {
	return append(hs.Copy(), other...)
}
