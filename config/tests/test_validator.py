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

        for domain in intDomains.values():
            self.assertTrue(n.check(domain))

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

if __name__ == "__main__":
    unittest.main()
