package main

type Header struct{ Name, Value string }
type Headers []Header

func (hs Headers) GetDefault(name string, defaultValue string) string {
	for i := range hs {
		if hs[i].Name == name {
			return hs[i].Value
		}
	}
	return defaultValue
}

func (hs Headers) Get(name string) string {
	return hs.GetDefault(name, "")
}

func (hs Headers) Copy() Headers {
	return append(Headers(nil), hs...)
}

func (hs Headers) Combine(other Headers) Headers {
	return append(hs.Copy(), other...)
}
