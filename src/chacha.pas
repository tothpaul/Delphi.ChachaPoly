unit chacha;
(*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.

Delphi version by Paul TOTH (12/04/2025)
*)
{$R-,Q-}
interface
{$POINTERMATH ON}
const
  CHACHA_MINKEYLEN = 16;
  CHACHA_NONCELEN = 8;
  CHACHA_CTRLEN = 8;
  CHACHA_STATELEN =  (CHACHA_NONCELEN+CHACHA_CTRLEN);
  CHACHA_BLOCKLEN = 64;

type
  chacha_ctx = record
    input: array[0..15] of Cardinal;
  end;

procedure chacha_keysetup(var x: chacha_ctx; k: PByte; kbits: Cardinal);
procedure chacha_ivsetup(var x: chacha_ctx; iv, counter: PByte);
procedure chacha_encrypt_bytes(var x: chacha_ctx;  m, c: PByte; bytes: Cardinal);

implementation

const
  sigma: AnsiString = 'expand 32-byte k';
  tau: AnsiString = 'expand 16-byte k';

function LSwap(L: Cardinal): Cardinal;
begin
  Result := Cardinal(Swap(L)) shl 16 + Swap(L shr 16);
end;

function U8TO32_LITTLE(p: PByte): Cardinal;
begin
  Result := Cardinal(p[0])
        or (Cardinal(p[1]) shl 8)
        or (Cardinal(p[2]) shl 16)
        or (Cardinal(p[3]) shl 24);
end;

procedure U32To8_Little(p: PByte; v: Cardinal); inline;
begin
  p[0] := Byte(v);
  p[1] := Byte(v shr 8);
  p[2] := Byte(v shr 16);
  p[3] := Byte(v shr 24);
end;

procedure chacha_keysetup(var x: chacha_ctx; k: PByte; kbits: Cardinal);
begin
  var constants: PByte;

  x.input[4] := U8TO32_LITTLE(k + 0);
  x.input[5] := U8TO32_LITTLE(k + 4);
  x.input[6] := U8TO32_LITTLE(k + 8);
  x.input[7] := U8TO32_LITTLE(k + 12);
  if (kbits = 256) then begin (* recommended *)
    Inc(k, 16);
    constants := PByte(sigma);
  end else begin (* kbits == 128 *)
    constants := PByte(tau);
  end;
  x.input[8] := U8TO32_LITTLE(k + 0);
  x.input[9] := U8TO32_LITTLE(k + 4);
  x.input[10] := U8TO32_LITTLE(k + 8);
  x.input[11] := U8TO32_LITTLE(k + 12);
  x.input[0] := U8TO32_LITTLE(constants + 0);
  x.input[1] := U8TO32_LITTLE(constants + 4);
  x.input[2] := U8TO32_LITTLE(constants + 8);
  x.input[3] := U8TO32_LITTLE(constants + 12);
end;

procedure chacha_ivsetup(var x: chacha_ctx; iv, counter: PByte);
begin
  if counter = nil then
  begin
    x.input[12] := 0;
  //x.input[13] := 0;
  end else begin
    x.input[12] := U8TO32_LITTLE(counter + 0);
//  x.input[13] := U8TO32_LITTLE(counter + 4);
  end;
  x.input[13] := U8TO32_LITTLE(iv + 0);
  x.input[14] := U8TO32_LITTLE(iv + 4);
  x.input[15] := U8TO32_LITTLE(iv + 8);
end;

function ROTATE(v, n: Cardinal): Cardinal; {$IFNDEF DEBUG}inline;{$ENDIF}
begin
  Result := (v shl n) or (v shr (32 - n));
end;

procedure QUARTERROUND(var a,b,c,d: Cardinal); {$IFNDEF DEBUG}inline;{$ENDIF}
begin
  a := a + b; d := ROTATE(d xor a,16);
  c := c + d; b := ROTATE(b xor c,12);
  a := a + b; d := ROTATE(d xor a, 8);
  c := c + d; b := ROTATE(b xor c, 7);
end;

procedure chacha_encrypt_bytes(var x: chacha_ctx;  m, c: PByte; bytes: Cardinal);
var
  x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15: Cardinal;
  j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15: Cardinal;
  ctarget: PByte;// = NULL;
  tmp: array[0..63] of Byte;
  i: Cardinal;
begin
  if (bytes = 0) then Exit;

  j0 := x.input[0];
  j1 := x.input[1];
  j2 := x.input[2];
  j3 := x.input[3];
  j4 := x.input[4];
  j5 := x.input[5];
  j6 := x.input[6];
  j7 := x.input[7];
  j8 := x.input[8];
  j9 := x.input[9];
  j10 := x.input[10];
  j11 := x.input[11];
  j12 := x.input[12];
  j13 := x.input[13];
  j14 := x.input[14];
  j15 := x.input[15];

  while true  do
  begin
    if (bytes < 64) then
    begin
//#if (USE_MEMCPY == 1)
//      memcpy(tmp, m, bytes);
      Move(m^, tmp, bytes);
//#else
//      for (i = 0;i < bytes;++i) tmp[i] = m[i];
//#endif
      m := @tmp;
      ctarget := c;
      c := @tmp;
    end;
    x0 := j0;
    x1 := j1;
    x2 := j2;
    x3 := j3;
    x4 := j4;
    x5 := j5;
    x6 := j6;
    x7 := j7;
    x8 := j8;
    x9 := j9;
    x10 := j10;
    x11 := j11;
    x12 := j12;
    x13 := j13;
    x14 := j14;
    x15 := j15;
    //for (i = 20;i > 0;i -= 2) {
    for i := 0 to 9 do
    begin
      QUARTERROUND( x0, x4, x8,x12);
      QUARTERROUND( x1, x5, x9,x13);
      QUARTERROUND( x2, x6,x10,x14);
      QUARTERROUND( x3, x7,x11,x15);
      QUARTERROUND( x0, x5,x10,x15);
      QUARTERROUND( x1, x6,x11,x12);
      QUARTERROUND( x2, x7, x8,x13);
      QUARTERROUND( x3, x4, x9,x14);
    end;
    x0 := x0 + j0;
    x1 := x1 + j1;
    x2 := x2 + j2;
    x3 := x3 + j3;
    x4 := x4 + j4;
    x5 := x5 + j5;
    x6 := x6 + j6;
    x7 := x7 + j7;
    x8 := x8 + j8;
    x9 := x9 + j9;
    x10 := x10 + j10;
    x11 := x11 + j11;
    x12 := x12 + j12;
    x13 := x13 + j13;
    x14 := x14 + j14;
    x15 := x15 + j15;

    x0 := x0 xor U8TO32_LITTLE(m + 0);
    x1 := x1 xor U8TO32_LITTLE(m + 4);
    x2 := x2 xor U8TO32_LITTLE(m + 8);
    x3 := x3 xor U8TO32_LITTLE(m + 12);
    x4 := x4 xor U8TO32_LITTLE(m + 16);
    x5 := x5 xor U8TO32_LITTLE(m + 20);
    x6 := x6 xor U8TO32_LITTLE(m + 24);
    x7 := x7 xor U8TO32_LITTLE(m + 28);
    x8 := x8 xor U8TO32_LITTLE(m + 32);
    x9 := x9 xor U8TO32_LITTLE(m + 36);
    x10 := x10 xor U8TO32_LITTLE(m + 40);
    x11 := x11 xor U8TO32_LITTLE(m + 44);
    x12 := x12 xor U8TO32_LITTLE(m + 48);
    x13 := x13 xor U8TO32_LITTLE(m + 52);
    x14 := x14 xor U8TO32_LITTLE(m + 56);
    x15 := x15 xor U8TO32_LITTLE(m + 60);

    Inc(j12);
    if (j12 = 0) then
    begin
      Inc(j13);
      //* stopping at 2^70 bytes per nonce is user's responsibility */
    end;

    U32TO8_LITTLE(c + 0,x0);
    U32TO8_LITTLE(c + 4,x1);
    U32TO8_LITTLE(c + 8,x2);
    U32TO8_LITTLE(c + 12,x3);
    U32TO8_LITTLE(c + 16,x4);
    U32TO8_LITTLE(c + 20,x5);
    U32TO8_LITTLE(c + 24,x6);
    U32TO8_LITTLE(c + 28,x7);
    U32TO8_LITTLE(c + 32,x8);
    U32TO8_LITTLE(c + 36,x9);
    U32TO8_LITTLE(c + 40,x10);
    U32TO8_LITTLE(c + 44,x11);
    U32TO8_LITTLE(c + 48,x12);
    U32TO8_LITTLE(c + 52,x13);
    U32TO8_LITTLE(c + 56,x14);
    U32TO8_LITTLE(c + 60,x15);

    if (bytes <= 64) then
    begin
      if (bytes < 64) then
      begin
//#if (USE_MEMCPY == 1)
//        memcpy(ctarget, c, bytes);
         Move(c^, ctarget^, bytes);
//#else
//        for (i = 0;i < bytes;++i) ctarget[i] = c[i];
//#endif
      end;
      x.input[12] := j12;
      x.input[13] := j13;
      Exit;
    end;
    Dec(bytes, 64);
    Inc(c, 64);
    Inc(m, 64);
  end;
end;

end.
