"""
Copyright (c) 2012, Nicholas Steicke
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the project author/s.
"""

import logging

import ipaddr

import dns.name

logger = logging.getLogger('DNS.Config.Validator')


class Validator:

    def __init__(self, config):
        self.config = config

        self.structure.check(config)


class Parameter:

    def check(self, value):
        return True

    def type(self):
        return None


class Basic(Parameter):

    def __init__(self, t):
        self.t = t

    def check(self, value):
        if type(value) == self.t:
            return True
        else:
            raise ValueError('Must be a %s' % (self.t,))

    def type(self):
        return self.t


class Name(Parameter):

    def check(self, value):
        try:
            if str(value):
                dns.name.from_text(value)
                return True
        except Exception:
            pass

        raise ValueError('Must be a valid DNS Name')

    def type(self):
        return dns.name.Name


class Address(Parameter):

    def __init__(self, version=None):
        if version != 4 and version != 6 and version is not None:
            raise ValueError('Version must be 4, 6 or None')

        self.version = version

    def check(self, value):
        try:
            addr = ipaddr.IPAddress(value)

            if self.version is None:
                return True
            else:
                if not addr.version == self.version:
                    raise ValueError(
                        'Not a valid IPv%d Address' % (self.version, )
                    )
                else:
                    return True
        except ValueError:
            raise ValueError('Not a valid Address')

    def type(self):
        return str


class List(Parameter):

    def __init__(self, contains):
        self.contains = contains

    def check(self, value):
        typeOfValue = type(value)

        if typeOfValue == list or typeOfValue == tuple or typeOfValue == set:
            value = list(value)
        else:
            raise ValueError('Not a valid List type.')

        for i in range(0, len(value)):
            try:
                if isinstance(self.contains, Parameter):
                    self.contains.check(value[i])
                else:
                    if type(value[i]) is not self.contains:
                        raise ValueError
            except ValueError as e:
                raise ValueError('Item at index %s: %s' % (i, e))

        return True

    def type(self):
        return list


class Dict(Parameter):

    def __init__(self, key, value):
        self.keyType = key
        self.valueType = value

        if isinstance(self.keyType, Parameter):
            self.__checkKey = self.keyType.check
        else:
            self.__checkKey = lambda x: self.__checkPrimitive(
                self.keyType,
                x
            )

        if isinstance(self.valueType, Parameter):
            self.__checkValue = self.valueType.check
        else:
            self.__checkValue = lambda x: self.__checkPrimitive(
                self.valueType,
                x
            )

    def __checkPrimitive(self, t, value):
        return type(value) == t

    def check(self, value):
        if not type(value) == dict:
            raise ValueError('Not a valid Dict')

        for key, item in value.items():
            try:
                if not self.__checkKey(key):
                    raise ValueError
            except ValueError as e:
                raise ValueError('Key %s: %s' % (key, e))

            try:
                if not self.__checkValue(item):
                    raise ValueError
            except ValueError as e:
                raise ValueError('Item at Key %s: %s' % (key, e))

        return True

    def type(self):
        return dict


class StructuredDict(Parameter):

    def __init__(self, structure):
        self.structure = structure

    def check(self, value):
        if not type(value) == dict:
            raise ValueError('Not a valid Dict')

        for key, validator in self.structure.items():
            if not key in value.keys():
                raise ValueError('Key %s not found' % (key,))

            try:
                validator.check(value[key])
            except ValueError as e:
                raise ValueError('Item at Key %s: %s' % (key, e))

    def type(self):
        return dict
