unit poly1305;
(*
poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64 bit addition
public domain

  C implementation of Daniel J. Bernstein's Poly1305 & Chacha20, RFC8439 (7539).

  Delphin version by Paul TOTH (12/04/2025)

*)
{$Q-,R-}
interface

const
  POLY1305_KEYLEN = 32;
  POLY1305_TAGLEN = 16;
  POLY1305_BLOCK_SIZE = 16;

type
  poly1305_context = record
    r: array[0..4] of Cardinal;
    h: array[0..4] of Cardinal;
    pad: array[0..3] of Cardinal;
    leftover: NativeInt;
    buffer: array[0..POLY1305_BLOCK_SIZE - 1] of Byte;
    _final: Byte;
  end;

procedure poly1305_init(var st: poly1305_context; key: PByte {32});
procedure poly1305_update(var st: poly1305_context; m: PByte; bytes: NativeInt);
procedure poly1305_finish(var st: poly1305_context; mac: PByte {16});

implementation

function U8TO32(p: PByte): Cardinal; inline;
begin
  Result :=
        ((Cardinal(p[0])       ) or
         (Cardinal(p[1]) shl  8) or
         (Cardinal(p[2]) shl 16) or
         (Cardinal(p[3]) shl 24));
end;

procedure U32TO8(p: PByte; v: Cardinal); inline;
begin
    p[0] := (v       ) and $ff;
    p[1] := (v shr  8) and $ff;
    p[2] := (v shr 16) and $ff;
    p[3] := (v shr 24) and $ff;
end;

procedure poly1305_init(var st: poly1305_context; key: PByte {32});
begin
    //* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st.r[0] := (U8TO32(@key[ 0])      ) and $3ffffff;
    st.r[1] := (U8TO32(@key[ 3]) shr 2) and $3ffff03;
    st.r[2] := (U8TO32(@key[ 6]) shr 4) and $3ffc0ff;
    st.r[3] := (U8TO32(@key[ 9]) shr 6) and $3f03fff;
    st.r[4] := (U8TO32(@key[12]) shr 8) and $00fffff;

    //* h = 0 */
    st.h[0] := 0;
    st.h[1] := 0;
    st.h[2] := 0;
    st.h[3] := 0;
    st.h[4] := 0;

    //* save pad for later */
    st.pad[0] := U8TO32(@key[16]);
    st.pad[1] := U8TO32(@key[20]);
    st.pad[2] := U8TO32(@key[24]);
    st.pad[3] := U8TO32(@key[28]);

    st.leftover := 0;
    st._final := 0;
end;

procedure poly1305_blocks(var st: poly1305_context; m: PByte; bytes: NativeInt);
var
  hibit: Cardinal;
  r0,r1,r2,r3,r4: Cardinal;
  s1,s2,s3,s4: Cardinal;
  h0,h1,h2,h3,h4: Cardinal;
  d0,d1,d2,d3,d4: UInt64;
  c: Cardinal;
begin
  if st._final <> 0 then
    hibit := 0
  else
    hibit := 1 shl 24; //* 1 << 128 */

  r0 := st.r[0];
  r1 := st.r[1];
  r2 := st.r[2];
  r3 := st.r[3];
  r4 := st.r[4];

  s1 := r1 * 5;
  s2 := r2 * 5;
  s3 := r3 * 5;
  s4 := r4 * 5;

  h0 := st.h[0];
  h1 := st.h[1];
  h2 := st.h[2];
  h3 := st.h[3];
  h4 := st.h[4];

  while (bytes >= POLY1305_BLOCK_SIZE) do
  begin
    //* h += m[i] */
    Inc(h0, (U8TO32(m+ 0)      ) and $3ffffff);
    Inc(h1, (U8TO32(m+ 3) shr 2) and $3ffffff);
    Inc(h2, (U8TO32(m+ 6) shr 4) and $3ffffff);
    Inc(h3, (U8TO32(m+ 9) shr 6) and $3ffffff);
    Inc(h4, (U8TO32(m+12) shr 8) or hibit);

    //* h *= r */
    d0 := UInt64(h0) * r0 + UInt64(h1) * s4 + UInt64(h2) * s3 + UInt64(h3) * s2 + UInt64(h4) * s1;
    d1 := UInt64(h0) * r1 + UInt64(h1) * r0 + UInt64(h2) * s4 + UInt64(h3) * s3 + UInt64(h4) * s2;
    d2 := UInt64(h0) * r2 + UInt64(h1) * r1 + UInt64(h2) * r0 + UInt64(h3) * s4 + UInt64(h4) * s3;
    d3 := UInt64(h0) * r3 + UInt64(h1) * r2 + UInt64(h2) * r1 + UInt64(h3) * r0 + UInt64(h4) * s4;
    d4 := UInt64(h0) * r4 + UInt64(h1) * r3 + UInt64(h2) * r2 + UInt64(h3) * r1 + UInt64(h4) * r0;

    //* (partial) h %= p */
                     c := Cardinal(d0 shr 26); h0 := Cardinal(d0) and $3ffffff;
    Inc(d1, c);      c := Cardinal(d1 shr 26); h1 := Cardinal(d1) and $3ffffff;
    Inc(d2, c);      c := Cardinal(d2 shr 26); h2 := Cardinal(d2) and $3ffffff;
    Inc(d3, c);      c := Cardinal(d3 shr 26); h3 := Cardinal(d3) and $3ffffff;
    Inc(d4, c);      c := Cardinal(d4 shr 26); h4 := Cardinal(d4) and $3ffffff;
    Inc(h0, c * 5);  c :=         (h0 shr 26); h0 :=           h0 and $3ffffff;
    Inc(h1, c);

    Inc(m, POLY1305_BLOCK_SIZE);
    Dec(bytes, POLY1305_BLOCK_SIZE);
  end;

  st.h[0] := h0;
  st.h[1] := h1;
  st.h[2] := h2;
  st.h[3] := h3;
  st.h[4] := h4;
end;

procedure poly1305_update(var st: poly1305_context; m: PByte; bytes: NativeInt);
var
  i: NativeInt;
begin
    //* handle leftover */
    if (st.leftover <> 0) then
    begin
        var want: NativeInt := (POLY1305_BLOCK_SIZE - st.leftover);
        if (want > bytes) then
            want := bytes;
        for i := 0 to want - 1 do
            st.buffer[st.leftover + i] := m[i];
        Dec(bytes, want);
        Inc(m, want);
        Inc(st.leftover, want);
        if (st.leftover < POLY1305_BLOCK_SIZE) then
            Exit;
        poly1305_blocks(st, @st.buffer, POLY1305_BLOCK_SIZE);
        st.leftover := 0;
    end;

    //* process full blocks */
    if (bytes >= POLY1305_BLOCK_SIZE) then
    begin
        var want: NativeInt := (bytes and not (POLY1305_BLOCK_SIZE - 1));
        poly1305_blocks(st, m, want);
        Inc(m, want);
        Dec(bytes, want);
    end;

    //* store leftover */
    if (bytes <> 0) then
    begin
//#if (USE_MEMCPY == 1)
//        memcpy(st->buffer + st->leftover, m, bytes);
       Move(m^, st.buffer[st.leftover], bytes);
//#else
//        for (i = 0; i < bytes; i++)
//            st->buffer[st->leftover + i] = m[i];
//#endif
        Inc(st.leftover, bytes);
    end;
end;

procedure poly1305_finish(var st: poly1305_context; mac: PByte {16});
var
    h0,h1,h2,h3,h4,c: Cardinal;
    g0,g1,g2,g3,g4: Cardinal;
    f: UInt64;
    mask: Cardinal;
begin
    //* process the remaining block */
    if (st.leftover <> 0) then
    begin
        var i : NativeInt := st.leftover;
        st.buffer[i] := 1; Inc(i);
        while i < POLY1305_BLOCK_SIZE do
        begin
          st.buffer[i] := 0;
          Inc(i);
        end;
        st._final := 1;
        poly1305_blocks(st, @st.buffer, POLY1305_BLOCK_SIZE);
    end;

    //* fully carry h */
    h0 := st.h[0];
    h1 := st.h[1];
    h2 := st.h[2];
    h3 := st.h[3];
    h4 := st.h[4];

                    c := h1 shr 26; h1 := h1 and $3ffffff;
    Inc(h2, c    ); c := h2 shr 26; h2 := h2 and $3ffffff;
    Inc(h3, c    ); c := h3 shr 26; h3 := h3 and $3ffffff;
    Inc(h4, c    ); c := h4 shr 26; h4 := h4 and $3ffffff;
    Inc(h0, c * 5); c := h0 shr 26; h0 := h0 and $3ffffff;
    Inc(h1, c    );

    //* compute h + -p */
    g0 := h0 + 5; c := g0 shr 26; g0 := g0 and $3ffffff;
    g1 := h1 + c; c := g1 shr 26; g1 := g1 and $3ffffff;
    g2 := h2 + c; c := g2 shr 26; g2 := g2 and $3ffffff;
    g3 := h3 + c; c := g3 shr 26; g3 := g3 and $3ffffff;
    g4 := h4 + c - (1 shl 26);

    //* select h if h < p, or h + -p if h >= p */
    mask := (g4 shr ((sizeof(Cardinal) * 8) - 1)) - 1;
    g0 := g0 and mask;
    g1 := g1 and mask;
    g2 := g2 and mask;
    g3 := g3 and mask;
    g4 := g4 and mask;
    mask := not mask;
    h0 := (h0 and mask) or g0;
    h1 := (h1 and mask) or g1;
    h2 := (h2 and mask) or g2;
    h3 := (h3 and mask) or g3;
    h4 := (h4 and mask) or g4;

    //* h = h % (2^128) */
    h0 := ((h0       ) or (h1 shl 26)) and $ffffffff;
    h1 := ((h1 shr  6) or (h2 shl 20)) and $ffffffff;
    h2 := ((h2 shr 12) or (h3 shl 14)) and $ffffffff;
    h3 := ((h3 shr 18) or (h4 shl  8)) and $ffffffff;

    //* mac = (h + pad) % (2^128) */
    f := UInt64(h0) + st.pad[0]             ; h0 := Cardinal(f);
    f := UInt64(h1) + st.pad[1] + (f shr 32); h1 := Cardinal(f);
    f := UInt64(h2) + st.pad[2] + (f shr 32); h2 := Cardinal(f);
    f := UInt64(h3) + st.pad[3] + (f shr 32); h3 := Cardinal(f);

    U32TO8(mac +  0, h0);
    U32TO8(mac +  4, h1);
    U32TO8(mac +  8, h2);
    U32TO8(mac + 12, h3);

    //* zero out the state */
    st.h[0] := 0;
    st.h[1] := 0;
    st.h[2] := 0;
    st.h[3] := 0;
    st.h[4] := 0;
    st.r[0] := 0;
    st.r[1] := 0;
    st.r[2] := 0;
    st.r[3] := 0;
    st.r[4] := 0;
    st.pad[0] := 0;
    st.pad[1] := 0;
    st.pad[2] := 0;
    st.pad[3] := 0;
end;

end.
