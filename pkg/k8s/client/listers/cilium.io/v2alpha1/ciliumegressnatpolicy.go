// Copyright 2017-2021 Authors of Cilium
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

// Code generated by lister-gen. DO NOT EDIT.

package v2alpha1

import (
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// CiliumEgressNATPolicyLister helps list CiliumEgressNATPolicies.
// All objects returned here must be treated as read-only.
type CiliumEgressNATPolicyLister interface {
	// List lists all CiliumEgressNATPolicies in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2alpha1.CiliumEgressNATPolicy, err error)
	// Get retrieves the CiliumEgressNATPolicy from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v2alpha1.CiliumEgressNATPolicy, error)
	CiliumEgressNATPolicyListerExpansion
}

// ciliumEgressNATPolicyLister implements the CiliumEgressNATPolicyLister interface.
type ciliumEgressNATPolicyLister struct {
	indexer cache.Indexer
}

// NewCiliumEgressNATPolicyLister returns a new CiliumEgressNATPolicyLister.
func NewCiliumEgressNATPolicyLister(indexer cache.Indexer) CiliumEgressNATPolicyLister {
	return &ciliumEgressNATPolicyLister{indexer: indexer}
}

// List lists all CiliumEgressNATPolicies in the indexer.
func (s *ciliumEgressNATPolicyLister) List(selector labels.Selector) (ret []*v2alpha1.CiliumEgressNATPolicy, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v2alpha1.CiliumEgressNATPolicy))
	})
	return ret, err
}

// Get retrieves the CiliumEgressNATPolicy from the index for a given name.
func (s *ciliumEgressNATPolicyLister) Get(name string) (*v2alpha1.CiliumEgressNATPolicy, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v2alpha1.Resource("ciliumegressnatpolicy"), name)
	}
	return obj.(*v2alpha1.CiliumEgressNATPolicy), nil
}
