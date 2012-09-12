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

import unittest
import re

import dns.name

import config.validator

intDomains = {
    'Afghanistan': 'افغانستا.icom.museum.',
    'Algeria': 'الجزائر.icom.museum.',
    'Austria': 'österreich.icom.museum.',
    'Bangladesh': 'বাংলাদেশ.icom.museum.',
    'Belarus': 'беларусь.icom.museum.',
    'Belgium': 'belgië.icom.museum.',
    'Bulgaria': 'българия.icom.museum.',
    'Chad': 'تشادر.icom.museum.',
    'China': '中国.icom.museum.',
    'Comoros': 'القمر.icom.museum.',
    'Cyprus': 'κυπρος.icom.museum.',
    'Czech Republic': 'českárepublika.icom.museum.',
    'Egypt': 'مصر.icom.museum.',
    'Greece': 'ελλάδα.icom.museum.',
    'Hungary': 'magyarország.icom.museum.',
    'Iceland': 'ísland.icom.museum.',
    'India': 'भारत.icom.museum.',
    'Iran': 'ايران.icom.museum.',
    'Ireland': 'éire.icom.museum.',
    'Israel': 'איקו״ם.ישראל.museum.',
    'Japan': '日本.icom.museum.',
    'Jordan': 'الأردن.icom.museum.',
    'Kazakhstan': 'қазақстан.icom.museum.',
    'Korea': '한국.icom.museum.',
    'Kyrgyzstan': 'кыргызстан.icom.museum.',
    'Laos': 'ລາວ.icom.museum.',
    'Lebanon': 'لبنان.icom.museum.',
    'Macedonia': 'македонија.icom.museum.',
    'Mauritania': 'موريتانيا.icom.museum.',
    'Mexico': 'méxico.icom.museum.',
    'Mongolia': 'монголулс.icom.museum.',
    'Morocco': 'المغرب.icom.museum.',
    'Nepal': 'नेपाल.icom.museum.',
    'Oman': 'عمان.icom.museum.',
    'Qatar': 'قطر.icom.museum.',
    'Romania': 'românia.icom.museum.',
    'Russia': 'россия.иком.museum.',
    'Serbia Montenegro': 'србијаицрнагора.иком.museum.',
    'Sri Lanka': 'இலங்கை.icom.museum.',
    'Spain': 'españa.icom.museum.',
    'Thailand': 'ไทย.icom.museum.',
    'Tunisia': 'تونس.icom.museum.',
    'Turkey': 'türkiye.icom.museum.',
    'Ukraine': 'украина.icom.museum.',
    'Vietnam': 'việtnam.icom.museum.'
}


class BasicTest(unittest.TestCase):

    def testType(self):
        b = config.validator.Basic(str)

        self.assertIs(b.type(), str)

    def testStr(self):
        b = config.validator.Basic(str)

        self.assertTrue(b.check('test string'))
        self.assertTrue(b.check("test string"))
        self.assertTrue(b.check("1234"))

    def testStrRaises(self):
        b = config.validator.Basic(str)
        self.assertRaises(ValueError, b.check, 1)
        self.assertRaises(ValueError, b.check, 1.3543)
        self.assertRaises(ValueError, b.check, (1, ))
        self.assertRaises(ValueError, b.check, [1, ])

    def testInt(self):
        b = config.validator.Basic(int)

        self.assertTrue(b.check(1))
        self.assertTrue(b.check(55674))
        self.assertTrue(b.check(-55674))

    def testIntRaises(self):
        b = config.validator.Basic(int)

        self.assertRaises(ValueError, b.check, '1')
        self.assertRaises(ValueError, b.check, 1.3543)
        self.assertRaises(ValueError, b.check, (1, ))
        self.assertRaises(ValueError, b.check, [1, ])

    def testFloat(self):
        b = config.validator.Basic(float)

        self.assertTrue(b.check(1.0))
        self.assertTrue(b.check(-556.74))

    def testFloatRaises(self):
        b = config.validator.Basic(float)

        self.assertRaises(ValueError, b.check, '1.0')
        self.assertRaises(ValueError, b.check, 1)
        self.assertRaises(ValueError, b.check, (1, ))
        self.assertRaises(ValueError, b.check, [1, ])


class NameTest(unittest.TestCase):

    def testNonLatinDomain(self):
        n = config.validator.Name()

        def intDomainTest(domain):
            self.assertTrue(n.check(domain))

        intDomainTest('افغانستا.icom.museum.')
        intDomainTest('الجزائر.icom.museum.')
        intDomainTest('österreich.icom.museum.')
        intDomainTest('বাংলাদেশ.icom.museum.')
        intDomainTest('беларусь.icom.museum.')
        intDomainTest('belgië.icom.museum.')
        intDomainTest('българия.icom.museum.')
        intDomainTest('تشادر.icom.museum.')
        intDomainTest('中国.icom.museum.')
        intDomainTest('القمر.icom.museum.')
        intDomainTest('κυπρος.icom.museum.')
        intDomainTest('českárepublika.icom.museum.')
        intDomainTest('مصر.icom.museum.')
        intDomainTest('ελλάδα.icom.museum.')
        intDomainTest('magyarország.icom.museum.')
        intDomainTest('ísland.icom.museum.')
        intDomainTest('भारत.icom.museum.')
        intDomainTest('ايران.icom.museum.')
        intDomainTest('éire.icom.museum.')
        intDomainTest('איקו״ם.ישראל.museum.')
        intDomainTest('日本.icom.museum.')
        intDomainTest('الأردن.icom.museum.')
        intDomainTest('қазақстан.icom.museum.')
        intDomainTest('한국.icom.museum.')
        intDomainTest('кыргызстан.icom.museum.')
        intDomainTest('ລາວ.icom.museum.')
        intDomainTest('لبنان.icom.museum.')
        intDomainTest('македонија.icom.museum.')
        intDomainTest('موريتانيا.icom.museum.')
        intDomainTest('méxico.icom.museum.')
        intDomainTest('монголулс.icom.museum.')
        intDomainTest('المغرب.icom.museum.')
        intDomainTest('नेपाल.icom.museum.')
        intDomainTest('عمان.icom.museum.')
        intDomainTest('قطر.icom.museum.')
        intDomainTest('românia.icom.museum.')
        intDomainTest('россия.иком.museum.')
        intDomainTest('србијаицрнагора.иком.museum.')
        intDomainTest('இலங்கை.icom.museum.')
        intDomainTest('españa.icom.museum.')
        intDomainTest('ไทย.icom.museum.')
        intDomainTest('تونس.icom.museum.')
        intDomainTest('türkiye.icom.museum.')
        intDomainTest('украина.icom.museum.')
        intDomainTest('việtnam.icom.museum.')

    def testInvalidDomain(self):
        n = config.validator.Name()

        self.assertRaises(ValueError, n.check, '..')
        self.assertRaises(ValueError, n.check, '..example.')
        self.assertRaises(ValueError, n.check, 'soemthing..example.')
        self.assertRaises(ValueError, n.check, 'example\\')

        name255 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
            "aaaaaaaaa"

        self.assertRaises(ValueError, n.check, name255)

    def testType(self):
        n = config.validator.Name()

        self.assertIs(n.type(), dns.name.Name)


class AddressTest(unittest.TestCase):

    def testOnlyV4orV6(self):
        self.assertRaises(ValueError, config.validator.Address, version=7)

        self.assertEqual(config.validator.Address(6).version, 6)
        self.assertEqual(config.validator.Address(4).version, 4)
        self.assertIs(config.validator.Address(None).version, None)
        self.assertIs(config.validator.Address().version, None)

    def testV4Addresses(self):
        """
        Addresses taken from ipaddr-py Test code

# Copyright 2007 Google Inc.
#  Licensed to PSF under a Contributor Agreement.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
        """
        def assertInvalidIp(val, addr):
            self.assertRaises(ValueError, val.check, addr)

        a = config.validator.Address()
        v4 = config.validator.Address(4)
        v6 = config.validator.Address(6)

        assertInvalidIp(a, '')
        assertInvalidIp(a, 'bogus')
        assertInvalidIp(a, 'bogus.com')

        assertInvalidIp(v4, '')
        assertInvalidIp(v4, '016.016.016.016')
        assertInvalidIp(v4, '016.016.016')
        assertInvalidIp(v4, '016.016')
        assertInvalidIp(v4, '016')
        assertInvalidIp(v4, '000.000.000.000')
        assertInvalidIp(v4, '000')
        assertInvalidIp(v4, '0x0a.0x0a.0x0a.0x0a')
        assertInvalidIp(v4, '0x0a.0x0a.0x0a')
        assertInvalidIp(v4, '0x0a.0x0a')
        assertInvalidIp(v4, '0x0a')
        assertInvalidIp(v4, '42.42.42.42.42')
        assertInvalidIp(v4, '42.42.42')
        assertInvalidIp(v4, '42.42')
        assertInvalidIp(v4, '42')
        assertInvalidIp(v4, '42..42.42')
        assertInvalidIp(v4, '42..42.42.42')
        assertInvalidIp(v4, '42.42.42.42.')
        assertInvalidIp(v4, '42.42.42.42...')
        assertInvalidIp(v4, '.42.42.42.42')
        assertInvalidIp(v4, '...42.42.42.42')
        assertInvalidIp(v4, '42.42.42.-0')
        assertInvalidIp(v4, '42.42.42.+0')
        assertInvalidIp(v4, '.')
        assertInvalidIp(v4, '...')
        assertInvalidIp(v4, '192.168.0.1.com')
        assertInvalidIp(v4, '12345.67899.-54321.-98765')
        assertInvalidIp(v4, '257.0.0.0')
        assertInvalidIp(v4, '42.42.42.-42')

        assertInvalidIp(v6, '3ffe::1.net')
        assertInvalidIp(v6, '3ffe::1::1')
        assertInvalidIp(v6, '1::2::3::4:5')
        assertInvalidIp(v6, '::7:6:5:4:3:2:')
        assertInvalidIp(v6, ':6:5:4:3:2:1::')
        assertInvalidIp(v6, '2001::db:::1')
        assertInvalidIp(v6, 'FEDC:9878')
        assertInvalidIp(v6, '+1.+2.+3.4')
        assertInvalidIp(v6, '1.2.3.4e0')
        assertInvalidIp(v6, '::7:6:5:4:3:2:1:0')
        assertInvalidIp(v6, '7:6:5:4:3:2:1:0::')
        assertInvalidIp(v6, '9:8:7:6:5:4:3::2:1')
        assertInvalidIp(v6, '0:1:2:3::4:5:6:7')
        assertInvalidIp(v6, '3ffe:0:0:0:0:0:0:0:1')
        assertInvalidIp(v6, '3ffe::10000')
        assertInvalidIp(v6, '3ffe::goog')
        assertInvalidIp(v6, '3ffe::-0')
        assertInvalidIp(v6, '3ffe::+0')
        assertInvalidIp(v6, '3ffe::-1')
        assertInvalidIp(v6, ':')
        assertInvalidIp(v6, ':::')
        assertInvalidIp(v6, '::1.2.3')
        assertInvalidIp(v6, '::1.2.3.4.5')
        assertInvalidIp(v6, '::1.2.3.4:')
        assertInvalidIp(v6, '1.2.3.4::')
        assertInvalidIp(v6, '2001:db8::1:')
        assertInvalidIp(v6, ':2001:db8::1')
        assertInvalidIp(v6, ':1:2:3:4:5:6:7')
        assertInvalidIp(v6, '1:2:3:4:5:6:7:')
        assertInvalidIp(v6, ':1:2:3:4:5:6:')
        assertInvalidIp(v6, '192.0.2.1/32')
        assertInvalidIp(v6, '2001:db8::1/128')
        assertInvalidIp(v6, '02001:db8::')

    def testWrongAddressTypeRaises(self):
        v4 = config.validator.Address(4)
        v6 = config.validator.Address(6)

        self.assertRaises(ValueError, v4.check, '::1')
        self.assertRaises(ValueError, v6.check, '127.0.0.1')

    def testValidAddress(self):
        a = config.validator.Address()
        v4 = config.validator.Address(4)
        v6 = config.validator.Address(6)

        self.assertTrue(a.check('127.0.0.1'))
        self.assertTrue(a.check('::1'))

        self.assertTrue(v4.check('127.0.0.1'))

        self.assertTrue(v6.check('::1'))

    def testType(self):
        a = config.validator.Address()

        self.assertIs(a.type(), str)


class ListTest(unittest.TestCase):

    def testListTypes(self):
        l = config.validator.List(str)

        self.assertRaisesRegex(
            ValueError,
            r'^Not a valid List type.$',
            l.check,
            {}
        )

    def testValidListBuiltin(self):
        strList = config.validator.List(str)
        self.assertTrue(strList.check(['a', 'b', 'c', 'd']))
        self.assertTrue(strList.check(['1', '2', '3', '4']))

        intList = config.validator.List(int)
        self.assertTrue(intList.check((1, 2, 3, 4)))

    def testValidListValidator(self):
        strList = config.validator.List(config.validator.Basic(str))
        self.assertTrue(strList.check(['a', 'b', 'c', 'd']))

    def testInvalidItemsInList(self):
        strList = config.validator.List(str)
        self.assertRaisesRegex(
            ValueError,
            r'^Item at index ',
            strList.check,
            ['a', 1, 'c', 'd']
        )

    def testType(self):
        strList = config.validator.List(str)

        self.assertTrue(strList.type(), list)


class DictTest(unittest.TestCase):

    def testIsADict(self):
        l = config.validator.Dict(str, int)

        self.assertRaisesRegex(
            ValueError,
            r'^Not a valid Dict$',
            l.check,
            []
        )

        self.assertRaisesRegex(
            ValueError,
            r'^Not a valid Dict$',
            l.check,
            (('a', 1), ('c', 2))
        )

    def testDictWithValidType(self):
        l = config.validator.Dict(str, int)

        t = {
            'a': 1,
            'b': 2,
            'c': 3
        }

        self.assertTrue(l.check(t))

    def testDictWithValidProperty(self):
        l = config.validator.Dict(
            config.validator.Name(),
            config.validator.Address()
        )

        t = {
            'example.': '127.0.0.1',
            'invalid.': '::1'
        }

        self.assertTrue(l.check(t))

    def testDictWithInvalidKeyType(self):
        l = config.validator.Dict(str, int)

        t = {
            'a': 1,
            2: 2,
            'c': 3
        }

        self.assertRaisesRegex(ValueError, r'^Key ', l.check, t)

    def testDictWithInvalidKeyProperty(self):
        l = config.validator.Dict(
            config.validator.Name(),
            config.validator.Address()
        )

        t = {
            '': '127.0.0.1',
            'invalid.': '::1'
        }

        self.assertRaisesRegex(ValueError, r'^Key ', l.check, t)

    def testDictWithInvalidValueType(self):
        l = config.validator.Dict(str, int)

        t = {
            'a': 1,
            'b': '2',
            'c': 3
        }

        self.assertRaisesRegex(ValueError, r'^Item at Key ', l.check, t)

    def testDictWithInvalidKeyProperty(self):
        l = config.validator.Dict(
            config.validator.Name(),
            config.validator.Address()
        )

        t = {
            'example.': '127.0.0.1',
            'invalid.': 'asgsafdgsafdg'
        }

        self.assertRaisesRegex(ValueError, r'^Item at Key ', l.check, t)

    def testType(self):
        l = config.validator.Dict(str, int)

        self.assertIs(l.type(), dict)


class StructuredDictTest(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
