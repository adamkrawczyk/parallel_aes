# Szyfr AES

## Historia

Na początku lat 90. stało się jasne, że potrzebny jest nowy standard w dziedzinie kryptografii. Wynikało to z faktu, że zarówno długość bloku (64 bity)
 jak i długość klucza (56 bitów) podstawowego algorytmu DES (wynalezionego w latach 70-tych) były zbyt małe dla przyszłych zastosowań (obecnie możliwe jest odzyskanie 56-bitowego klucza DES przy użyciu sieci komputerów lub specjalistycznego sprzętu). W odpowiedzi na ten problem amerykański Narodowy Instytut Norm i Technologii (NIST) zainicjował
konkurs na nowy szyfr blokowy, który miał nosić nazwę Advanced Encryption Standard lub AES.
W przeciwieństwie do procesu projektowania DES, który był utrzymywany w ścisłej tajemnicy, projekt AES
został przeprowadzony publicznie. Wiele grup z całego świata przedstawiło projekty szyfru AES.
Ostatecznie wybrano pięć algorytmów, znanych jako finaliści AES, które poddano szczegółowym badaniom.

Były to
- MARS opracowany przez grupę z IBM,
- RC6 od grupy z RSA Security,
- Twofish od grupy z Counterpane, UC Berkeley i innych,
- Serpent od grupy trzech naukowców z Izraela, Norwegii i Wielkiej Brytanii,
- Rijndael od pary młodych belgijskich kryptografów (Vincent Rijmen i Joan Daemen).

Wreszcie jesienią 2000 roku NIST ogłosił, że ogólnym zwycięzcą AES został wybrany
Rijndael.

## Wstęp do zasad działania

DES i wszyscy finaliści AES są przykładami iterowanych szyfrów blokowych. Szyfry blokowe uzyskują
swoje bezpieczeństwo poprzez wielokrotne użycie prostej funkcji zaokrąglania. Funkcja zaokrąglająca przyjmuje n-bitowy blok
i zwraca n-bitowy blok, gdzie n jest rozmiarem bloku całego szyfru. Liczba rund
r może być zmienna lub stała. Ogólną zasadą jest, że zwiększenie liczby rund zwiększa
poziom bezpieczeństwa szyfru blokowego.

Aby umożliwić opis, każda runda musi być odwracalna. AES jest algorytmem z kluczem symetrycznym, co oznacza, że ten sam klucz jest używany zarówno do szyfrowania, jak i odszyfrowywania danych. AES ma stały rozmiar bloku 128 bitów i rozmiar klucza 128, 192 lub 256 bitów.

## Opis algorytmu

```
Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
begin
byte state[4,Nb]
state = in

AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4

for round = 1 step 1 to Nr–1
SubBytes(state) // See Sec. 5.1.1
ShiftRows(state) // See Sec. 5.1.2
MixColumns(state) // See Sec. 5.1.3
AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
end for

SubBytes(state)
ShiftRows(state)
AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
out = state

end
```
