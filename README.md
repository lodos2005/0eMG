# 0eMG! - Your 0e collision finder

> Is There Another Type Juggling Challenge? 0eMG!


![0eMG! Logo](https://img.shields.io/badge/0eMG!-Type%20Juggling%20Finder-blue)

A powerful tool to find hash type juggling vulnerabilities in various hash algorithms.

## English

### Introduction

**0eMG!** is a high-performance tool designed to find strings that produce hash values starting with "0e" followed by digits only - a pattern that leads to type juggling vulnerabilities in languages like PHP.

The main purpose of this tool is to demonstrate that type juggling challenges in CTFs, hack challenges, and hackathons are now easily solvable, making them less viable as security puzzles.

### What is Type Juggling?

In weakly typed languages like PHP, when comparing a string that looks like a scientific notation with zero exponent (e.g., "0e123456") with the integer 0 using loose comparison (==), the string is interpreted as a float, resulting in:

```php
"0e123456" == 0  // Evaluates to true!
```

This means two completely different strings that produce hash values starting with "0e" followed by digits will be considered equal when compared with `==`.

### Features

- Multi-threaded processing for maximum performance
- Supports multiple hash algorithms: MD5, SHA1, SHA256, CRC32, and their double-hash variants
- Configurable base string
- Adjustable random string length
- Prefix or suffix mode (random+base or base+random)
- Interactive or command-line usage
- Real-time progress monitoring

### Installation

```bash
git clone https://github.com/lodos2005/0emg.git
cd 0emg
go build
```

### Usage

Basic usage:

```bash
./oemg run
```

With custom options:

```bash
./oemg -hash md5 -mode prefix -base test123 -min 3 -max 10 run
```

Check a specific string:

```bash
./oemg -hash md5 check
```

### Supported Hash Types

- `md5`: Single MD5 hash
- `md5md5`: Double MD5 hash (MD5 of MD5)
- `sha1`: SHA-1 hash
- `sha1sha1`: Double SHA-1 hash
- `sha256`: SHA-256 hash
- `sha256sha256`: Double SHA-256 hash
- `crc32`: CRC32 checksum

### Command-line Options

```
Options:
  -base string
        Base string (default "lodos2005")
  -batch int
        Batch size for each thread (default 100000)
  -charset string
        Character set to use
  -hash string
        Hash algorithm: md5, md5md5, sha1, sha1sha1, sha256, sha256sha256, crc32 (default "md5")
  -max int
        Maximum random character length (default 50)
  -min int
        Minimum random character length (default 10)
  -mode string
        Mode: 'prefix' (random+base) or 'suffix' (base+random) (default "suffix")
  -threads int
        Number of threads to use (default: number of CPUs)
```

### License

MIT License

---

## Türkçe

### Giriş

**0eMG!**, çeşitli hash algoritmalarında "0e" ile başlayıp sadece rakamlarla devam eden hash değerleri üreten string'leri bulmak için tasarlanmış yüksek performanslı bir araçtır. Bu tür hash değerleri, PHP gibi dillerde type juggling güvenlik açıklarına yol açar.

Bu aracın temel amacı, CTF'lerde, hack yarışmalarında ve hackathon'larda hala sorulan type juggling sorularının artık basit bir şekilde çözülebildiğini göstermek ve bu tür soruların güvenlik bulmacası olarak geçerliliğini azaltmaktır.

### Type Juggling Nedir?

PHP gibi zayıf tipli dillerde, sıfır üssü olan bilimsel gösterim formatındaki bir string (örn. "0e123456") ile 0 tam sayısını gevşek karşılaştırma (==) kullanarak karşılaştırdığınızda, string float olarak yorumlanır ve sonuç:

```php
"0e123456" == 0  // True olarak değerlendirilir!
```

Bu, "0e" ile başlayıp sonrasında sadece rakamlar içeren hash değerleri üreten iki tamamen farklı string, `==` ile karşılaştırıldığında eşit kabul edilecek demektir.

### Özellikler

- Maksimum performans için çok iş parçacıklı işleme
- Birden fazla hash algoritması desteği: MD5, SHA1, SHA256, CRC32 ve bunların çift hash varyantları
- Yapılandırılabilir temel string
- Ayarlanabilir rastgele string uzunluğu
- Önek veya sonek modu (rastgele+temel veya temel+rastgele)
- Etkileşimli veya komut satırı kullanımı
- Gerçek zamanlı ilerleme izleme

### Kurulum

```bash
git clone https://github.com/lodos2005/0emg.git
cd 0emg
go build
```

### Kullanım

Temel kullanım:

```bash
./oemg run
```

Özel seçeneklerle:

```bash
./oemg -hash md5 -mode prefix -base test123 -min 3 -max 10 run
```

Belirli bir string'i kontrol etme:

```bash
./oemg -hash md5 check
```

### Desteklenen Hash Tipleri

- `md5`: Tek MD5 hash
- `md5md5`: Çift MD5 hash (MD5'in MD5'i)
- `sha1`: SHA-1 hash
- `sha1sha1`: Çift SHA-1 hash
- `sha256`: SHA-256 hash
- `sha256sha256`: Çift SHA-256 hash
- `crc32`: CRC32 sağlama toplamı

### Komut Satırı Seçenekleri

```
Seçenekler:
  -base string
        Temel string (varsayılan "lodos2005")
  -batch int
        Her iş parçacığı için parti boyutu (varsayılan 100000)
  -charset string
        Kullanılacak karakter seti
  -hash string
        Hash algoritması: md5, md5md5, sha1, sha1sha1, sha256, sha256sha256, crc32 (varsayılan "md5")
  -max int
        Maksimum rastgele karakter uzunluğu (varsayılan 50)
  -min int
        Minimum rastgele karakter uzunluğu (varsayılan 10)
  -mode string
        Mod: 'prefix' (random+base) veya 'suffix' (base+random) (varsayılan "suffix")
  -threads int
        Kullanılacak iş parçacığı sayısı (varsayılan: CPU sayısı)
```

### Lisans

MIT Lisansı
