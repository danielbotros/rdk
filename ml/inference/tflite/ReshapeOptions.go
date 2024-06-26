// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package tflite

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type ReshapeOptions struct {
	_tab flatbuffers.Table
}

func GetRootAsReshapeOptions(buf []byte, offset flatbuffers.UOffsetT) *ReshapeOptions {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &ReshapeOptions{}
	x.Init(buf, n+offset)
	return x
}

func GetSizePrefixedRootAsReshapeOptions(buf []byte, offset flatbuffers.UOffsetT) *ReshapeOptions {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &ReshapeOptions{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func (rcv *ReshapeOptions) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *ReshapeOptions) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *ReshapeOptions) NewShape(j int) int32 {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		a := rcv._tab.Vector(o)
		return rcv._tab.GetInt32(a + flatbuffers.UOffsetT(j*4))
	}
	return 0
}

func (rcv *ReshapeOptions) NewShapeLength() int {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.VectorLen(o)
	}
	return 0
}

func (rcv *ReshapeOptions) MutateNewShape(j int, n int32) bool {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		a := rcv._tab.Vector(o)
		return rcv._tab.MutateInt32(a+flatbuffers.UOffsetT(j*4), n)
	}
	return false
}

func ReshapeOptionsStart(builder *flatbuffers.Builder) {
	builder.StartObject(1)
}
func ReshapeOptionsAddNewShape(builder *flatbuffers.Builder, newShape flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(newShape), 0)
}
func ReshapeOptionsStartNewShapeVector(builder *flatbuffers.Builder, numElems int) flatbuffers.UOffsetT {
	return builder.StartVector(4, numElems, 4)
}
func ReshapeOptionsEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
