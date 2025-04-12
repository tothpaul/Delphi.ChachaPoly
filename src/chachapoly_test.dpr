program chachapoly_test;
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

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  chachapoly in 'chachapoly.pas',
  chacha in 'chacha.pas',
  poly1305 in 'poly1305.pas';

function chachapoly_test_rfc7539: Integer;
var
  tag: array[0..15] of byte;
  ct : array[0..113] of byte;
  c2 : array[0..113] of AnsiChar;
  i, ret: Integer;
  ctx: chachapoly_ctx;

const
  key: array[0..31] of byte = (
    $80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
    $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f
  );
  ad: array[0..11] of byte = (
    $50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7
  );
const
  pt: AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
  nonce: array[0..11] of Byte = (
    $07, $00, $00, $00,
    $40, $41, $42, $43, $44, $45, $46, $47
  );
  tag_verify: array[0..15] of Byte = (
    $1a, $e1, $0b, $59, $4f, $09, $e2, $6a, $7e, $90, $2e, $cb, $d0, $60, $06, $91
  );
  ct_verify: array[0..113] of Byte = (
    $d3, $1a, $8d, $34, $64, $8e, $60, $db, $7b, $86, $af, $bc, $53, $ef, $7e, $c2,
    $a4, $ad, $ed, $51, $29, $6e, $08, $fe, $a9, $e2, $b5, $a7, $36, $ee, $62, $d6,
    $3d, $be, $a4, $5e, $8c, $a9, $67, $12, $82, $fa, $fb, $69, $da, $92, $72, $8b,
    $1a, $71, $de, $0a, $9e, $06, $0b, $29, $05, $d6, $a5, $b6, $7e, $cd, $3b, $36,
    $92, $dd, $bd, $7f, $2d, $77, $8b, $8c, $98, $03, $ae, $e3, $28, $09, $1b, $58,
    $fa, $b3, $24, $e4, $fa, $d6, $75, $94, $55, $85, $80, $8b, $48, $31, $d7, $bc,
    $3f, $f4, $de, $f0, $8e, $4b, $7a, $9d, $e5, $76, $d2, $65, $86, $ce, $c6, $4b,
    $61, $16
  );

begin
  Assert(Length(pt) = 114);
  chachapoly_init(ctx, @key, 256);
  chachapoly_crypt(ctx, @nonce, @ad, 12, Pointer(pt), 114, @ct, @tag, 16, 1);
  for i := 0 to 113 do
      if (ct[i] <> ct_verify[i]) then
        Exit(-2);

  for i := 0 to  15 do
      if (tag[i] <> tag_verify[i]) then
          Exit(-3);

  Result := chachapoly_crypt(ctx, @nonce, @ad, 12, @ct, 114, @c2, @tag, 16, 0);
end;

function chachapoly_test_auth_only: Integer;
var
  tag: array[0..15] of Byte;
  i: Integer;
  ctx: chachapoly_ctx;
const
  key: array[0..31] of Byte = (
    $80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
    $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f
  );
  pt: AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
  nonce: array[0..11] of Byte = (
    $07, $00, $00, $00,
    $40, $41, $42, $43, $44, $45, $46, $47
  );
  tag_verify: array[0..15] of Byte = (
    $03, $DC, $D0, $84, $04, $67, $80, $E6, $39, $50, $67, $0D, $3B, $BC, $C8, $95
  );
begin
    chachapoly_init(ctx, @key, 256);
    chachapoly_crypt(ctx, @nonce, Pointer(pt), 114, nil, 0, nil, @tag, 16, 1);

    for i := 0 to 15 do
        if tag[i] <> tag_verify[i] then
            Exit(-3);

    Result := chachapoly_crypt(ctx, @nonce, Pointer(pt), 114, nil, 0, nil, @tag, 16, 0);
end;

begin
  try
    var res := chachapoly_test_rfc7539();
    WriteLn('rfc7539 = ', res);
    res := chachapoly_test_auth_only();
    WriteLn('auth_only = ', res);
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
