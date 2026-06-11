package bincoder

import (
	"reflect"

	"github.com/rotisserie/eris"
	"github.com/samber/lo"
)

var canonicalScalarKinds = []reflect.Kind{
	reflect.Bool,
	reflect.Uint8,
	reflect.Uint32,
	reflect.String,
}

func Canonicalize(v any) ([]byte, error) {
	value, err := canonicalStructValue(v)
	if err != nil {
		return nil, err
	}

	enc := NewEncoder()
	structType := value.Type()
	for i := range structType.NumField() {
		fieldType := structType.Field(i)
		fieldValue := value.Field(i)

		if !fieldType.IsExported() {
			return nil, eris.Errorf("canonicalize field %q: unexported fields are not supported", fieldType.Name)
		}

		if err := encodeCanonicalField(enc, fieldType, fieldValue); err != nil {
			return nil, err
		}
	}

	return append([]byte(nil), enc.Result()...), nil
}

func canonicalStructValue(v any) (reflect.Value, error) {
	value := reflect.ValueOf(v)
	if !value.IsValid() {
		return reflect.Value{}, eris.New("canonicalize: nil value")
	}

	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return reflect.Value{}, eris.New("canonicalize: nil pointer")
		}
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return reflect.Value{}, eris.Errorf("canonicalize expects a struct or pointer to struct, got %s", value.Type())
	}

	return value, nil
}

func encodeCanonicalField(enc *Encoder, fieldType reflect.StructField, fieldValue reflect.Value) error {
	if fieldType.Type.Kind() == reflect.Struct {
		return eris.Errorf("canonicalize field %q: struct type %s is not supported", fieldType.Name, fieldType.Type)
	}

	switch {
	case fieldType.Type.Kind() == reflect.Slice && fieldType.Type.Elem().Kind() == reflect.Uint8:
		enc.Bytes(fieldValue.Bytes())
	case lo.Contains(canonicalScalarKinds, fieldType.Type.Kind()):
		switch fieldType.Type.Kind() {
		case reflect.Bool:
			enc.Bool(fieldValue.Bool())
		case reflect.Uint8:
			enc.Byte(byte(fieldValue.Uint()))
		case reflect.Uint32:
			enc.U32(uint32(fieldValue.Uint()))
		case reflect.String:
			enc.Bytes([]byte(fieldValue.String()))
		}
	default:
		return eris.Errorf("canonicalize field %q: unsupported type %s", fieldType.Name, fieldType.Type)
	}

	if err := enc.Err(); err != nil {
		return eris.Wrapf(err, "canonicalize field %q", fieldType.Name)
	}

	return nil
}
