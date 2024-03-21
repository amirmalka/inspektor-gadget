// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package formatters

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// Keep this aligned with include/gadget/types.h
const (
	// Name of the type that gadgets should use to store an L3 endpoint.
	L3EndpointTypeName = "gadget_l3endpoint_t"

	// Name of the type that gadgets should use to store an L4 endpoint.
	L4EndpointTypeName = "gadget_l4endpoint_t"

	// Name of the type to store a timestamp
	TimestampTypeName = "gadget_timestamp"
)

type formattersOperator struct{}

func (f *formattersOperator) Name() string {
	return "formatters"
}

func (f *formattersOperator) Init(params *params.Params) error {
	return nil
}

func (f *formattersOperator) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (f *formattersOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext) (operators.DataOperatorInstance, error) {
	inst := &formattersOperatorInstance{
		// l3endpointFields: make(map[datasource.DataSource][]converter),
		// l4endpointFields: make(map[datasource.DataSource][]converter),
		converters: make(map[datasource.DataSource][]converter),
	}
	logger := gadgetCtx.Logger()
	// Find things we can enrich
	for _, ds := range gadgetCtx.GetDataSources() {
		var converters []converter
		logger.Debugf("formatterOperator inspecting datasource %q", ds.Name())
		for _, r := range replacers {
			fields := ds.GetFieldsWithTag(r.selectors...)
			if len(fields) == 0 {
				continue
			}
			logger.Debugf("> found %d fields for replacer %v", len(fields), r.selectors)
			for _, field := range fields {
				replFunc, err := r.replace(ds, field)
				if err != nil {
					logger.Debugf(">  skipping field %q: %v", field.Name(), err)
					continue
				}
				if replFunc == nil {
					continue
				}
				converters = append(converters, converter{
					name:     r.name,
					src:      field,
					replacer: replFunc,
					priority: r.priority,
				})
			}
		}
		if len(converters) > 0 {
			inst.converters[ds] = converters
		}
	}
	// Don't run, if we don't have anything to do
	if len(inst.converters) == 0 {
		return nil, nil
	}
	return inst, nil
}

type converter struct {
	name     string
	src      datasource.FieldAccessor
	replacer func(datasource.Payload) error
	priority int
}

type replacer struct {
	name string

	// selectors describes which fields to look for
	selectors []string

	// replace will be called for incoming data with the source and target fields set
	replace func(datasource.DataSource, datasource.FieldAccessor) (func(datasource.Payload) error, error)

	// priority to be used when subscribing to the DataSource
	priority int
}

// careful: order and priority matter both!
var replacers = []replacer{
	{
		name:      "timestamp",
		selectors: []string{"type:" + TimestampTypeName},
		replace: func(ds datasource.DataSource, in datasource.FieldAccessor) (func(p datasource.Payload) error, error) {
			// Read annotations to allow user-defined behavior; this needs to be documented // TODO
			annotations := in.Annotations()

			hideOriginal := true
			if hide := annotations["formatters.timestamp.hide"]; hide == "false" {
				hideOriginal = false
			}
			if hideOriginal {
				in.SetHidden(true)
			}

			timestampFormat := time.RFC3339Nano
			if format := annotations["formatters.timestamp.format"]; format != "" {
				timestampFormat = format
			}

			outName := in.Name() + "_str"
			if out := annotations["formatters.timestamp.target"]; out != "" {
				outName = out
			}

			out, err := ds.AddField(outName)
			if err != nil {
				return nil, nil
			}

			return func(p datasource.Payload) error {
				inBytes := in.Get(p)
				switch len(inBytes) {
				default:
					return nil
				case 8:
					// TODO: WallTimeFromBootTime() converts too much for this, create a new func that does less
					correctedTime := gadgets.WallTimeFromBootTime(ds.ByteOrder().Uint64(inBytes))
					ds.ByteOrder().PutUint64(inBytes, uint64(correctedTime))
					t := time.Unix(0, int64(correctedTime))
					return out.Set(p, []byte(t.Format(timestampFormat)))
				}
			}, nil
		},
		priority: 0,
	},
	{
		name:      "l3endpoint",
		selectors: []string{"type:" + L3EndpointTypeName},
		replace: func(ds datasource.DataSource, in datasource.FieldAccessor) (func(p datasource.Payload) error, error) {
			// We do some length checks in here - since we expect the in field to be part of an eBPF struct that
			// is always sized statically, we can avoid checking the individual entries later on.
			in.SetHidden(true)
			ips := in.GetSubFieldsWithTag("type:gadget_ip_addr_t")
			if len(ips) != 1 {
				return nil, fmt.Errorf("expected %d gadget_ip_addr_t field, got %d", 1, len(ips))
			}
			if ips[0].Size() != 16 {
				return nil, fmt.Errorf("expected gadget_ip_addr_t to have 16 bytes")
			}
			versions := in.GetSubFieldsWithTag("name:version")
			if len(versions) != 1 {
				return nil, fmt.Errorf("expected exactly 1 version field")
			}
			out, err := in.AddSubField("string", datasource.WithTags("l3string"))
			if err != nil {
				return nil, fmt.Errorf("adding string field: %w", err)
			}
			return func(p datasource.Payload) error {
				ip := ips[0].Get(p)
				v := versions[0].Get(p)
				if len(v) != 1 {
					return nil
				}
				var err error
				switch v[0] {
				case 4:
					err = out.Set(p, []byte(net.IP(ip[:4]).String()))
				case 6:
					err = out.Set(p, []byte(net.IP(ip).String()))
				default:
					return fmt.Errorf("invalid IP version for l3endpoint")
				}
				return err
			}, nil
		},
		priority: 0,
	},
	{
		name:      "l4endpoint",
		selectors: []string{"type:" + L4EndpointTypeName},
		replace: func(ds datasource.DataSource, in datasource.FieldAccessor) (func(p datasource.Payload) error, error) {
			// We do some length checks in here - since we expect the in field to be part of an eBPF struct that
			// is always sized statically, we can avoid checking the individual entries later on.
			in.SetHidden(true)
			// Get accessors to required fields
			ports := in.GetSubFieldsWithTag("name:port")
			if len(ports) != 1 {
				return nil, fmt.Errorf("expected exactly 1 port field")
			}
			if ports[0].Size() != 2 {
				return nil, fmt.Errorf("port size expected to be 2")
			}
			l3 := in.GetSubFieldsWithTag("type:" + L3EndpointTypeName)
			if len(l3) != 1 {
				return nil, fmt.Errorf("expected exactly 1 l3endpoint field")
			}
			l3strings := l3[0].GetSubFieldsWithTag("l3string")
			if len(l3strings) != 1 {
				return nil, fmt.Errorf("expected exactly 1 l3string field")
			}
			l3strings[0].SetHidden(true)
			out, err := in.AddSubField("string")
			if err != nil {
				return nil, fmt.Errorf("adding string field: %w", err)
			}
			return func(p datasource.Payload) error {
				port := binary.BigEndian.Uint16(ports[0].Get(p))
				out.Set(p, []byte(fmt.Sprintf("%s:%d", string(l3strings[0].Get(p)), port)))
				return nil
			}, nil
		},
		priority: 1,
	},
}

type formattersOperatorInstance struct {
	converters map[datasource.DataSource][]converter
}

func (f *formattersOperatorInstance) Name() string {
	return "formatters"
}

func (f *formattersOperatorInstance) ParamDescs(gadgetCtx operators.GadgetContext) params.ParamDescs {
	return nil
}

func (f *formattersOperatorInstance) Priority() int {
	return 0
}

func (f *formattersOperatorInstance) Prepare(gadgetCtx operators.GadgetContext, params *params.Params) error {
	for ds, converters := range f.converters {
		for _, c := range converters {
			conv := c
			ds.Subscribe(func(ds datasource.DataSource, gp datasource.GadgetPayload) error {
				return gp.Each(func(p datasource.Payload) error {
					return conv.replacer(p)
				})
			}, conv.priority)
		}
	}
	return nil
}

func (f *formattersOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (f *formattersOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func init() {
	operators.RegisterDataOperator(&formattersOperator{})
}
