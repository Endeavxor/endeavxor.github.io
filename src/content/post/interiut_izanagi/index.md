---
title: "[RE] Izanagi | InterIUT 2024"
description: "Writeup du challenge 'Izanagi' lors du CTF InterIUT 2024"
publishDate: "01 June 2024"
tags: ["reverse",]
draft: false
coverImage:
  src: "./cover.jpeg"
  alt: ""
---


## Description
- CTF : https://x.com/CTF_Inter_IUT/
- Challmaker : Endeavxor
- Difficulté : Moyen
- Nombre de résolution : 1



## Reverse statique

```sh
(venv) endeavxor@deb:~/InterIUT2024/Izanagi$ file izanagi

izanagi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=262aaed07af94db568a9579ad453d8edf23da745, for GNU/Linux 3.2.0, stripped
```

La fonction `main` n'est pas bien grande ni complexe : 

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char userInput[60]; // [rsp+0h] [rbp-40h] BYREF
  int i; // [rsp+3Ch] [rbp-4h]

  printf(format, a2, a3);
  fgets(userInput, 54, stdin);
  for ( i = 0; i <= 52; ++i )
    byte_404060[i] ^= userInput[i];
  if ( !memcmp(byte_404060, &unk_4040A0, 0x35uLL) && !strncmp(userInput, "interiut{", 9uLL) )
    puts("Bravo, vous avez le bon flag. Vraiment trivial nan ;)");
  else
    puts("Nop");
  return 0LL;
}
```

Il s'agit d'un simple `xor` entre notre entrée utilisateur et un tableau d'octets codé en dur `byte_404060` et le résultat de cette opération est comparé à un autre tableau codé en dur. Plutôt simple, on effectue tout ça : 


```py
a = [0,0,0,0,0,0,0,0,80,113,35,78,118,70,33,16,13,103,52,123,81,87,125,35,79,124,92,83,70,33,17,114,112,55,106,60,61,116,117,89,28,115,39,87,38,107,118,76,103,32,44,94,41]
b = [105,110,116,101,114,105,117,116,20,24,71,17,15,41,84,79,127,2,85,23,61,46,34,87,39,21,50,56,25,72,101,45,7,88,31,80,89,43,23,60,67,7,79,54,82,52,19,45,20,89,19,127,84]

for i in range(len(a)):
    print(chr( a[i] ^ b[i] ),end="")
```

**interiutDid_you_really_think_it_would_be_that_easy?!}**

Et .... et on se retrouve avec un flag mal formé :/. Après une rapide vérification dynamique avec `gdb`, on confirme que notre entrée utilisateur est correcte ainsi que les deux tableaux ce qui est étrange. Il y a donc deux possibilités :

- Le challmaker s'est trompé *(bonsoir non)*
- Il y a quelque chose qu'on ne saisit pas encore sur le fonctionnement du binaire, bien que cela semble invraisemblable étant donné que la fonction `main` ne contient que la logique vue plus haut


Pour pouvoir comprendre ce qui se passe, il y avait 2 approches : 
- `strace`
- Regarder les fonctions strippé présentes dans le binaire, car il y en a tout juste 5 

Dans les 2 cas, on observe un appel système à `ptrace` connu pour être détourné afin de vérifier si le programme est débuggé. La fonction en question `sub_401166`. En regardant les références croisées sur cette fonction, on observe qu'elle est référencée ici : 


```
.text:0000000000401166 sub_401166      proc near               ; DATA XREF: .init_array:0000000000403DF8↓o
```

Après une rapide recherche sur la section `.init_array`, on apprend ceci : 

> .init_array contains pointers to blocks of code that need to be executed
when an application is being initialized (before main() is called).  Its
used for a number of things, but the primary use is in C++ for running
static constructors; a secondary use that is sometimes used is to
initialize IO systems in the C library.

On comprend donc que cette fonction est appelée avant `main`.

Analysons donc plus en profondeur la fonction :

```c
void **hidden_function()
{
  void **result; // rax
  __int64 v1; // rdx
  __int64 v2; // rcx
  char *v3; // r10
  __int64 v4; // rcx
  __int64 v5; // rcx

  result = (void **)sys_ptrace(0LL, 0LL, 0LL, 0LL);
  if ( result != (void **)-1LL )
  {
    result = &_libc_start_main_ptr;
    v2 = 144LL;
    do
    {
      result = (void **)((char *)result + 1);
      --v2;
    }
    while ( v2 );
    v3 = (char *)&loc_4012AC;
    v4 = 3476LL;
    do
    {
      ++v3;
      --v4;
    }
    while ( v4 );
    v5 = 45LL;
    do
    {
      *((_BYTE *)result + v1) = v3[v1];
      ++v1;
      --v5;
    }
    while ( v5 );
  }
  return result;
}
```

Dans les grandes lignes, cette fonction va dans un premier temps vérifier si un débugger est présent avec l'appel système `ptrace`. Si c'est le cas, elle ne fait rien et quitte la fonction. Si au contraire il n'y a pas de debugger, deux adresses mémoires sont récupérées et le contenu de la première est écris dans la seconde. Les adresses de bases sont étranges : `_libc_start_main_ptr` et `loc_4012AC`. Elles subissent un décalage de `+144` pour la première et `+3476` pour la seconde. Cette fonction à 2 objectifs :

- De tromper les outils de **reverse statique** tel qu'`IDA` ou `Ghidra` afin que ces derniers ne créer pas de références croisées directement auprès des vraies zones mémoires manipulées pour que le joueur ne s'aperçoive pas de la machination *(on verra que les zones mémoires ci-dessous sont utilisée dans la fonction `main`, et donc qu'un œil attentif aurait vu une seconde référence un peu louche)*.

- De tromper les outils de **reverse dynamique** tel que `gdb`, car comme vu plus haut, il ne se passe rien si un debugger est présent, donc le comportement semble concorder avec ce qui a été analysé en statique dans `main`

La première adresse *(qui sera donc la destination)* pointe vers `.data:0000000000404068` qui n'est autre que le tableau d'octets *(+ 8 octets valant 0 du au format de flag interiut qui ne change pas)* utilisé pour effectuer le `xor` dans `main` . Il est remplacé par le contenu de la seconde adresse pointant vers `.rodata:0000000000402040` qui est la chaîne de caractère *(+ 8 octets valant 0 du au format de flag interiut qui ne change pas)*: `ous avez le bon flag. Vraiment trivial nan ;)`

## Résolution

Il suffit donc d'appliquer le `xor` avec cette chaîne de caractère : 


```py
a = [0,0,0,0,0,0,0,0] + [ord(c) for c in "ous avez le bon flag. Vraiment trivial nan ;)"]
b = [105,110,116,101,114,105,117,116,20,24,71,17,15,41,84,79,127,2,85,23,61,46,34,87,39,21,50,56,25,72,101,45,7,88,31,80,89,43,23,60,67,7,79,54,82,52,19,45,20,89,19,127,84]

for i in range(len(a)):
    print(chr( a[i] ^ b[i] ),end="")
```

**Flag: interiut{m41n_15_n07_ALwAyS_7h3_f1r57_7H1n9_3X3Cu73D}**
