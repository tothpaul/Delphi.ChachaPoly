unit chachapoly;
(*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Grigori Goronzy <goronzy@kinoho.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *)

(*
  C implementation of Daniel J. Bernstein's Poly1305 & Chacha20, RFC8439 (7539).

  Delphin version by Paul TOTH (12/04/2025)
*)

interface

uses
  chacha, poly1305;

const
  CHACHAPOLY_OK = 0;
  CHACHAPOLY_INVALID_MAC = -1;

type
  chachapoly_ctx = record
    cha_ctx: chacha_ctx;
  end;

function chachapoly_init(var ctx: chachapoly_ctx; key: Pointer; key_len: Integer): Integer;
function chachapoly_crypt(var ctx: chachapoly_ctx; nonce,
        ad: Pointer; ad_len: Integer; input: Pointer; input_len: Integer;
        output, tag: Pointer; tag_len, encrypt: Integer): Integer;

implementation

function memcmp_eq(a, b: PByte; n: Integer): Integer;
begin
  Result := 0;
  for var i := 0 to n - 1 do
  begin
      Result := Result or (a^ xor b^);
      Inc(a);
      Inc(b);
  end;
end;

procedure poly1305_get_tag(poly_key, ad: PByte;
        ad_len: Integer; ct: PByte; ct_len: Integer; tag: PByte);
var
  poly: poly1305_context;
  left_over: Cardinal;
  len: UInt64;
  pad: array[0..15] of Byte;
begin
  poly1305_init(poly, poly_key);
  FillChar(pad, SizeOf(pad), 0);

  //* associated data and padding */
  poly1305_update(poly, ad, ad_len);
  left_over := ad_len mod 16;
  if (left_over <> 0) then
    poly1305_update(poly, @pad, 16 - left_over);

  //* payload and padding */
  poly1305_update(poly, ct, ct_len);
  left_over := ct_len mod 16;
  if (left_over <> 0) then
      poly1305_update(poly, @pad, 16 - left_over);

  //* lengths */
  len := ad_len;
  poly1305_update(poly, @len, 8);
  len := ct_len;
  poly1305_update(&poly, @len, 8);

  poly1305_finish(poly, tag);
end;

function chachapoly_init(var ctx: chachapoly_ctx; key: Pointer; key_len: Integer): Integer;
begin
    assert((key_len = 128) or (key_len = 256));

    FillChar(ctx, SizeOf(ctx), 0);
    chacha_keysetup(ctx.cha_ctx, key, key_len);
    Result := CHACHAPOLY_OK;
end;

function chachapoly_crypt(var ctx: chachapoly_ctx; nonce,
        ad: Pointer; ad_len: Integer; input: Pointer; input_len: Integer;
        output, tag: Pointer; tag_len, encrypt: Integer): Integer;
var
  poly_key: array[0..CHACHA_BLOCKLEN - 1] of Byte;
  calc_tag: array[0..POLY1305_TAGLEN-1] of Byte;
const
  one: array[0..3] of Byte = (1, 0, 0, 0);
begin
  (* initialize keystream and generate poly1305 key *)
  FillChar(poly_key, SizeOf(poly_key), 0);
  chacha_ivsetup(ctx.cha_ctx, nonce, nil);
  chacha_encrypt_bytes(ctx.cha_ctx, @poly_key, @poly_key, sizeof(poly_key));

  (* check tag if decrypting *)
  if (encrypt = 0) and (tag_len <> 0) then
  begin
    poly1305_get_tag(@poly_key, ad, ad_len, input, input_len, @calc_tag);
    if (memcmp_eq(@calc_tag, tag, tag_len) <> 0) then
        Exit(CHACHAPOLY_INVALID_MAC);
  end;

  //* crypt data */
  chacha_ivsetup(ctx.cha_ctx, nonce, @one);
  chacha_encrypt_bytes(ctx.cha_ctx, input,
                       output, input_len);

  //* add tag if encrypting */
  if (encrypt <> 0) and (tag_len <> 0) then
  begin
      poly1305_get_tag(@poly_key, ad, ad_len, output, input_len, @calc_tag);
      //memcpy(tag, calc_tag, tag_len);
      Move(calc_tag, tag^, tag_len);
  end;

  Result := CHACHAPOLY_OK;
end;

end.
