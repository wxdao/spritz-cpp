#include <cstddef>
#include "spritz.hpp"

Spritz::Spritz() {
    for (int v = 0; v < 256; ++v) {
        s[v] = byte(v);
    }
}

void Spritz::swap(int a, int b) {
    byte tmp = s[a];
    s[a] = s[b];
    s[b] = tmp;
}

void Spritz::absorb(ByteArray i) {
    for (auto b : i) {
        absorbByte(b);
    }
}

void Spritz::absorbByte(byte b) {
    absorbNibble(b & 0x0f);
    absorbNibble(b >> 4);
}

void Spritz::absorbNibble(int x) {
    if (x == 128) {
        shuffle();
    }
    swap(a++, 128 + x);
}

void Spritz::absorbStop() {
    if (a++ == 128) {
        shuffle();
    }
}

void Spritz::shuffle() {
    whip(512);
    crush();
    whip(512);
    crush();
    whip(512);
    a = 0;
}

void Spritz::whip(int r) {
    for (int v = 0; v < r; ++v) {
        update();
    }
    w = (w + 2) & 0xff;
}

void Spritz::crush() {
    for (int v = 0; v < 128; ++v) {
        if (s[v] > s[255 - v]) {
            swap(v, 255 - v);
        }
    }
}

ByteArray Spritz::squeeze(size_t r) {
    if (a > 0) {
        shuffle();
    }
    ByteArray p(r);
    for (int v = 0; v < r; ++v) {
        p[v] = drip();
    }

    return p;
}

byte Spritz::drip() {
    if (a > 0) {
        shuffle();
    }
    update();
    return output();
}

void Spritz::update() {
    i = (i + w) & 0xff;
    j = (k + s[(j + s[i]) & 0xff]) & 0xff;
    k = (k + i + s[j]) & 0xff;
    swap(i, j);
}

byte Spritz::output() {
    z = s[(j + s[(i + s[(z + k) & 0xff]) & 0xff]) & 0xff];
    return byte(z);
}

void Spritz::crypt(ByteArray &data, ByteArray key, ByteArray iv) {
    Spritz obj;
    obj.absorb(key);
    if (iv.size() > 0) {
        obj.absorbStop();
        obj.absorb(iv);
    }
    auto sq = obj.squeeze(data.size());
    for (int v = 0; v < data.size(); ++v) {
        data[v] ^= sq[v];
    }
}

ByteArray Spritz::hash(ByteArray data, int bits) {
    Spritz obj;
    obj.absorb(data);
    obj.absorbStop();
    int r = (bits + 7) / 8;
    obj.absorbByte(byte(r));
    return obj.squeeze(size_t(r));
}

ByteArray Spritz::mac(ByteArray data, ByteArray key, int bits) {
    Spritz obj;
    obj.absorb(key);
    obj.absorbStop();
    obj.absorb(data);
    obj.absorbStop();
    int r = (bits + 7) / 8;
    obj.absorbByte(byte(r));
    return obj.squeeze(size_t(r));
}
















