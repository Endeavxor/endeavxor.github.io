---
title: "[RE] deck_decoder | Midnight Flag - Operation BACKSLASH"
description: "Writeup du challenge deck_decoder lors du CTF Midnight Flag - Operation BACKSLASH"
publishDate: "01 May 2024"
tags: ["reverse","qiling","CTF"]
draft: false
coverImage:
  src: "./cover.jpeg"
  alt: ""
updatedDate: "02 May 2024"
---

## Description
- CTF : https://ctftime.org/event/2295/
- Challmaker : prince2lu
- Nombre de résolution : < 10 *(aux dernières nouvelles)*


## Reverse statique

Le binaire est assez classique : 


```sh
$ file deck_decoder

deck_decoder: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```


J'ai déjà réalisé la partie renommage et retypage en statique pour une grande partie du binaire afin de faciliter la lecture du writeup. Cependant le binaire était **initialement strippé**, ça n'était donc pas aussi *trivial* que ça en aura l'air. 


```c
__int64 __fastcall main(int argc, char **argv, char **a3)
{
  unsigned __int8 v3; // al
  int seed; // [rsp+14h] [rbp-2Ch]
  char *shuffled_hardcoded_ptr; // [rsp+18h] [rbp-28h]
  char *malloc_shellcode_shuffled; // [rsp+20h] [rbp-20h]
  char *userInput; // [rsp+30h] [rbp-10h]

  if ( argc != 2 || (seed = atoi(argv[1]), seed > 2000) )
  {
    printf("Usage: %s <pin>\n", *argv);
    exit(1);
  }
  srand(seed);
  shuffled_hardcoded_ptr = (char *)shuffle_hardcoded_ptr((char **)&hardcoded_array_ptr, 2279);
  malloc_shellcode_shuffled = decrypt_rc4_shellcode((char **)shuffled_hardcoded_ptr);
  mprotect_RWX((unsigned __int64)malloc_shellcode_shuffled);
  userInput = (char *)malloc(0x1EuLL);
  if ( !userInput )
    exit(1);
  fgets(userInput, 30, stdin);
  signal(11, handler);                          // SIGSEGV
  signal(4, handler);                           // SIGILL
  v3 = check_flag(userInput, (__int64 (__fastcall *)(__int64))malloc_shellcode_shuffled, 29LL);
  printf(":%c\n", v3 + (unsigned int)'(');
  return 0LL;
}
```

Avant de rentrer dans les différentes fonctions, notons que : 

- Le binaire récupère un argument passé au lancement et attend un **entier qui doit être inférieur à 2000**. Cet argument sera ensuite **utilisé pour initialiser un générateur de nombre pseudo-aléatoire**.

- `hardcoded_array_ptr` est un tableau de pointeur qui est passé en paramètre à la première fonction. En voici un aperçu :  

```
.data:0000000000014120 hardcoded_array_ptr dq offset unk_F004  ; DATA XREF: main+B0↑o
.data:0000000000014128                 dq offset unk_F00B
.data:0000000000014130                 dq offset unk_F00E
.data:0000000000014138                 dq offset unk_F013
.data:0000000000014140                 dq offset unk_F01A
.data:0000000000014148                 dq offset unk_F01F
.data:0000000000014150                 dq offset unk_F023
.data:0000000000014158                 dq offset unk_F029
.data:0000000000014160                 dq offset unk_F02D
.data:0000000000014168                 dq offset unk_F032
```

Ces pointeurs référencent des blocs consécutifs :

```
.rodata:000000000000F004 unk_F004        db    5                 ; DATA XREF: .data:hardcoded_array_ptr↓o
.rodata:000000000000F005                 db  6Eh ; n
.rodata:000000000000F006                 db 0F2h
.rodata:000000000000F007                 db  67h ; g
.rodata:000000000000F008                 db 0FEh
.rodata:000000000000F009                 db  82h
.rodata:000000000000F00A                 db    0
.rodata:000000000000F00B unk_F00B        db    1                 ; DATA XREF: .data:0000000000014128↓o
.rodata:000000000000F00C                 db  2Bh ; +
.rodata:000000000000F00D                 db    0
.rodata:000000000000F00E unk_F00E        db    3                 ; DATA XREF: .data:0000000000014130↓o
.rodata:000000000000F00F                 db 0EDh
.rodata:000000000000F010                 db  9Ch
.rodata:000000000000F011                 db  1Bh
.rodata:000000000000F012                 db    0
.rodata:000000000000F013 unk_F013        db    5                 ; DATA XREF: .data:0000000000014138↓o
.rodata:000000000000F014                 db 0CBh
.rodata:000000000000F015                 db  38h ; 8
.rodata:000000000000F016                 db    0
.rodata:000000000000F017                 db  8Bh
.rodata:000000000000F018                 db 0EFh
.rodata:000000000000F019                 db    0
```

### shuffle_hardcoded_ptr


La première fonction appelée est la suivante :


```c
_QWORD *__fastcall shuffle_hardcoded_ptr(char **hardcoded_array_ptr, int _2279)
{
  unsigned __int64 i; // [rsp+18h] [rbp-28h]
  unsigned __int64 j; // [rsp+20h] [rbp-20h]
  int *malloc_indexes; // [rsp+28h] [rbp-18h]
  _QWORD *malloc_ptr_shuffled; // [rsp+30h] [rbp-10h]

  malloc_indexes = (int *)malloc(4LL * _2279);
  if ( !malloc_indexes )
    goto LABEL_10;
  for ( i = 0LL; i < _2279; ++i )
    malloc_indexes[i] = i;
  malloc_ptr_shuffled = malloc(8LL * (_2279 + 1));
  if ( !malloc_ptr_shuffled )
LABEL_10:
    exit(1);
  fisher_yates_shuffle((__int64)malloc_indexes, _2279);
  for ( j = 0LL; j < _2279; ++j )
    malloc_ptr_shuffled[malloc_indexes[j]] = hardcoded_array_ptr[j];
  free(malloc_indexes);
  return malloc_ptr_shuffled;
}
```


Après analyse, on comprend qu'une des fonctions appelées est `fisher_yates_shuffle` :



```c
unsigned __int64 __fastcall fisher_yates_shuffle(int *malloc_indexes, int _2279)
{
  int random_number; // eax
  int i; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = _2279 - 1; i > 0; --i )
  {
    random_number = rand();
    swap(&malloc_indexes[i], &malloc_indexes[random_number % (i + 1)]);
  }
  return v5 - __readfsqword(0x28u);
}
```


Le mélange de **Fisher-Yates** est un algorithme permettant de générer des arrangements aléatoires, autrement dit de mélanger. Dans notre cas, un premier tableau d'index de 0 à 2278 est créé avant d'être mélangé. Ce tableau est ensuite parcouru afin de récupérer un index *(qui n'est donc plus ordonné)* qui sera utilisé pour récupérer un pointeur présent `hardcoded_array_ptr` vu précédemment. 

L'élément important à noté ici et qui impactera la résolution est que **le mélange de `hardcoded_array_ptr` est dépendant de l'argument passé lors du lancement du binaire**. En effet, ce dernier initialise le générateur de nombre pseudo-aléatoire utilisé ici dans l'algorithme pour effectuer le mélange *(`rand()`)*.


### decrypt_rc4_shellcode

Une fois le mélange du tableau de pointeur effectué, ce dernier est passé en paramètre à `decrypt_rc4_shellcode`. Le renommage est plutôt explicite. La fonction se présente de la sorte :


```c
_BYTE *__fastcall decrypt_rc4_shellcode(char **shuffled_hardcoded_ptr)
{
  unsigned __int8 currentShellcodeSize; // [rsp+1Fh] [rbp-441h]
  unsigned __int64 i; // [rsp+20h] [rbp-440h]
  __int64 index; // [rsp+28h] [rbp-438h]
  unsigned __int64 j; // [rsp+30h] [rbp-430h]
  unsigned __int64 k; // [rsp+38h] [rbp-428h]
  _BYTE *malloc_shellcode_shuffled; // [rsp+40h] [rbp-420h]
  _BYTE *currentShellcode; // [rsp+48h] [rbp-418h]
  char RC4_KEY_STRUCT[1032]; // [rsp+50h] [rbp-410h] BYREF
  unsigned __int64 v10; // [rsp+458h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  for ( i = 0LL; shuffled_hardcoded_ptr[i]; ++i )
    len += (unsigned __int8)*shuffled_hardcoded_ptr[i];
  malloc_shellcode_shuffled = malloc(len);
  if ( !malloc_shellcode_shuffled )
    exit(1);
  index = 0LL;
  memset(RC4_KEY_STRUCT, 0, sizeof(RC4_KEY_STRUCT));
  RC4_set_key(RC4_KEY_STRUCT, 16LL, &RC4_KEY);
  for ( j = 0LL; j < i; ++j )
  {
    currentShellcodeSize = *shuffled_hardcoded_ptr[j];
    currentShellcode = malloc(currentShellcodeSize);
    RC4(RC4_KEY_STRUCT, currentShellcodeSize, shuffled_hardcoded_ptr[j] + 1, currentShellcode);
    for ( k = 0LL; k < currentShellcodeSize; ++k )
      malloc_shellcode_shuffled[index++] = currentShellcode[k];
    free(currentShellcode);
  }
  return malloc_shellcode_shuffled;
}
```

Cette fonction permet de comprendre un peu mieux les blocs de données auxquels font référence les pointeurs dans le tableau vu initialement : 

- Une boucle parcourt chaque pointeur du tableau
- Le premier élément référencé par les pointeurs est une taille de données
- Cette taille de données définit le nombre d'octets qui suit devant être déchiffré en RC4 *(la clé est codée en dur)*
- Ceci explique pourquoi chaque morceau fini par un octet null *(nécessaire car la fonction RC4 de la libcrypto.so.3 s'attend à un char\*)*

Si on reprend deux des blocs vus plus haut : 

```
.rodata:000000000000F00B unk_F00B        db    1                 ; DATA XREF: .data:0000000000014128↓o
.rodata:000000000000F00C                 db  2Bh ; +
.rodata:000000000000F00D                 db    0
.rodata:000000000000F00E unk_F00E        db    3                 ; DATA XREF: .data:0000000000014130↓o
.rodata:000000000000F00F                 db 0EDh
.rodata:000000000000F010                 db  9Ch
.rodata:000000000000F011                 db  1Bh
.rodata:000000000000F012                 db    0
```

- `unk_F00B` contient **1** octet effectif *(sans compter l'octet nul)* qui sera déchiffré
- `unk_F00E` contient **3** octets effectifs *(sans compter l'octet nul)* qui seront déchiffrés


Ici, le renommage mentionne un **shellcode** bien qu'il faille continuer l'analyse afin de pouvoir l'affirmer.


### mprotect_RWX

Il ne faudra pas longtemps pour se rendre compte que les données déchiffrées représentent probablement un shellcode, car la protection de la zone mémoire où sont stockées ces dernières est modifiée afin de pouvoir lire, écrire, mais surtout **exécuter** les données qui s'y trouvent :

```c
unsigned __int64 __fastcall mprotect_RWX(unsigned __int64 a1)
{
  void *addr; // [rsp+20h] [rbp-10h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  addr = (void *)(-sysconf(30) & a1);
  if ( mprotect(addr, len, 7) == -1 )
  {
    perror("mprotect failed");
    free((void *)a1);
  }
  return v3 - __readfsqword(0x28u);
}
```


### check_flag

Après modification de la protection de la zone mémoire, une entrée utilisateur est récupérée avant d'être passé à la dernière fonction, `check_flag` : 

```c
__int64 __fastcall check_flag(
        const char *userInput,
        __int64 (__fastcall *malloc_shellcode_shuffled)(__int64),
        __int64 _29)
{
  unsigned __int8 mustBe1; // [rsp+2Fh] [rbp-21h]
  __int64 rdi; // [rsp+30h] [rbp-20h]
  unsigned __int64 i; // [rsp+38h] [rbp-18h]
  unsigned __int64 j; // [rsp+40h] [rbp-10h]

  rdi = 0LL;
  mustBe1 = 1;
  if ( _29 == strlen(userInput) )
  {
    for ( i = 0LL; i < _29 - 1; ++i )
    {
      for ( j = 0LL; j <= 6; j += 2LL )
        rdi |= ((__int64)userInput[i + 1] << (8 * ((unsigned __int8)j + 1))) | ((__int64)userInput[i] << (8 * (unsigned __int8)j));
      mustBe1 &= malloc_shellcode_shuffled(rdi) == hardcoded_expected_result[i];
      rdi = 0LL;
    }
  }
  else
  {
    return 0;
  }
  return mustBe1;
}
```


La fonction est plutôt simple hormis pour le paramètre passé à notre shellcode via le registre `rdi` que j'expliciterais plus bas. Notre shellcode *(exécutable grâce au précédent appel à `mprotect`)* est appelé pour chaque caractère hormis le dernier de notre entrée utilisateur. Une fois le shellcode exécuté, sa valeur de retour *(présente dans le registre `rax`)* sera comparé à un tableau de valeur codé en dur dont voici un extrait :

```
.data:0000000000014020 ; _QWORD hardcoded_expected_result[28]
.data:0000000000014020 hardcoded_expected_result dq 751E22F6AFDC1D1Ah, 25E2D8737E1EE778h, 5FA5062A2A463E93h
.data:0000000000014020                                         ; DATA XREF: check_flag+D7↑o
.data:0000000000014038                 dq 31E402F96E8BDF97h, 835BE6989055C8F7h, 5D96E686BBBB53FAh
.data:0000000000014050                 dq 0ECE6FF58CDD9D31Ah, 0C21A2CBC37DBC25Fh, 504E496158267321h
.data:0000000000014068                 dq 1E7F1D0186F1EC8Ch, 177A0713EE72684Ch, 701183528F5AC6CFh
.data:0000000000014080                 dq 0B732A1AFDC2F5679h, 76C06994CE3A61BCh, 0F5F06AB9884DE54Fh
.data:0000000000014098                 dq 701183528F5AC6CFh, 5A37ADF157A8C201h, 0C094D5287D091C4Fh
.data:00000000000140B0                 dq 0F5F06AB9884DE54Fh, 3DAA050C3B50450Eh, 0A93C0AF6A0E9C41Ch
.data:00000000000140C8                 dq 0F5D4CBAB3B2C88A3h, 0A27A01B298EC17A8h, 5FCEFDDD776A26F0h
.data:00000000000140E0                 dq 0DEBDE5DBB1C1C4B3h, 0E08C572F24190ABh, 0D512D32829E4869h
.data:00000000000140F8                 dq 0FFBD122F4A434777h
```


Le paramètre passé à notre shellcode utilise l'i-ème et l'i-ème+1 caractère de notre entrée utilisateur et effectue des opérations binaires dessus. Après un rapide coup d'oeil avec `gdb`, on s'aperçoit que les 2 caractères dépendant de i sont dupliqués pour remplir un registre de 64 bits. Ceci explique pourquoi la boucle s'arrête un cran avant la fin de l'entrée utilisateur. 

L'objectif ici est qu'après exécution de notre shellcode sur les différents paramètres qui constitue notre entrée, les résultats soient respectivement égaux aux valeurs codées en dur. 



### Fin d'analyse

Une fois la vérification faites, le binaire affiche `:(` pour une mauvaise entrée utilisateur ou `:)` dans le cas où l'on aurait trouvé le bon flag. Voici une vision macro de ce que fait le binaire :

- L'argument passé au lancement du binaire doit être strictement inférieur à 2000 et est utilisé comme graine du générateur de nombre pseudo-aléatoire
- Utilisation de l'algorithme de Fisher-Yates afin de mélanger un tableau de pointeur. Le mélange est dépendant de notre entrée utilisateur car l'algorithme utilise `rand()` dont le générateur est initialisé par la graine précédente.
- Chaque pointeur de ce tableau référence un morceau de shellcode chiffré via RC4
- Chaque morceau est déchiffré
- La protection de la zone mémoire où se trouve ce shellcode est modifiée pour pouvoir l'exécuter
- Le shellcode est appelé plusieurs fois en utilisant 2 octets consécutifs *(fenêtre glissante de 1 octet vers la droite à chaque itération)* de l'entrée utilisateur jusqu'à la fin
- Les résultats obtenus doivent être égaux à ceux codés en dur


Afin de pouvoir résoudre le challenge, il faut résoudre les deux problématiques suivantes : 

- Il y a potentiellement 2000 shellcodes possibles qui dépendent de l'argument au lancement.
- Une fois le bon shellcode trouvé il faudra le résoudre pour obtenir les sorties voulues


## Résolution
### Diminution du nombre de shellcodes possible

Jusqu'à 2000 shellcodes est inenvisageable à traiter à la main. Cependant, nous allons tirer parti d'une des caractéristiques du binaire : les morceaux de shellcodes sont mélangés, il y a donc de forte chance qu'une fois rassembler certains blocs génèrent des instructions *(SIGILL)* ou des accès mémoires *(SIGSEGV)*  invalides après le déchiffrement via RC4, causant le crash du programme et le non-affichage du smiley `:(`. Ces deux cas sont d'ailleurs gérés au sein du binaire via la mise en place d'un handler via `signal`. Avec un petit script bash on peut donc réduire le nombre de shellcodes possible : 


```sh
#!/bin/bash

# Fonction pour exécuter le binaire avec chaque entier de 1 à 2000
eliminate() {
    # Liste d'exclusion
    exclusion=(1219)
    for i in {1..2000}
    do
        # Vérifie si l'entier est dans la liste d'exclusion
        if [[ " ${exclusion[@]} " =~ " ${i} " ]]; then
            continue
        fi

        # Exécute le binaire avec l'entier actuel et sauvegarde la sortie
        output=$(echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAA | ./deck_decoder $i)

        # Vérifie si la sortie contient :) ou :(
        if [[ $output == *":)"* ]] || [[ $output == *":("* ]]; then
            echo $i
        fi
    done
}

# Appelle la fonction
eliminate
```

Pour une raison dont je n'ai pas cherché à investiguer, le PIN 1219 bloquait le binaire d'où la création d'une liste d'exclusion.

```sh
$ ./eliminate_invalide_shellcode.sh
23
214
248
272
541
734
748
912
1087
1203
1343
1387
1640
1665
```

Nous réduisons donc les possibilités à 15 shellcodes ! Cela reste raisonnable pour regarder à la main avec `gdb` le contenu *(c'est d'ailleurs ce que j'ai effectué durant le CTF)* mais nous allons opter pour une solution plus propre.

### Identification du bon shellcode avec qiling

Pour analyser les précédents shellcode, nous allons utiliser `qiling`[^1] qui va nous permettre d'émuler le binaire et de l'instrumenter. Le script va ensuite afficher les premières instructions en langage d'assemblage des différents shellcodes possibles via `capstone`[^2]. Pour ce faire, on va *hooker* l'instruction suivant l'appel à la fonction `decrypt_rc4_shellcode`, qui contiendra dans RAX le pointeur vers le shellcode déchiffré et mélangé :

[^1]: https://github.com/qilingframework/qiling
[^2]: https://github.com/capstone-engine/capstone

```c
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.const import QL_INTERCEPT
from capstone import *

g_shellcode_size=-1

def getShellCode(ql: Qiling) -> None:
    global g_shellcode_size
    global base_addr
    data = ql.mem.read(ql.arch.regs.read("RAX") , 100) #g_shellcode_size)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(data, base_addr):
      print("[*] {} {}".format(i.mnemonic, i.op_str))
    ql.emu_stop()

def getShellCodeSize(ql: Qiling) -> None:
    global g_shellcode_size
    g_shellcode_size=ql.arch.regs.read("RAX")

for possibleSeed in [23,214,248,272,541,734,748,912,1087,1203,1343,1387,1640,1665]:
    print("Current SEED =>", possibleSeed)
    rootfs = r'/qiling/rootfs2/qiling-rootfs-09f5c5b0d51ac50b99ff7067ce02afa67e3c8a98/x8664_linux_glibc2.39/'
    ql = Qiling(["/qiling/rootfs/x8664_linux/deck_decoder",str(possibleSeed)], rootfs, verbose=QL_VERBOSE.OFF)

    base_addr = ql.loader.images[0].base
    hook_addr_shellcode = base_addr + 0xEA89
    hook_addr_shellcode_size = base_addr + 0xE45A

    ql.hook_address(getShellCodeSize,hook_addr_shellcode_size)
    ql.hook_address(getShellCode,hook_addr_shellcode)

    ql.run()
```

Nous obtenons trois types de shellcode : 

- Retour immédiat : 

```
[*] ret
[*] imul edx, dword ptr [rsi + 0x2e15e7a3], -0x10
[*] jo 0x55555555405f
[*] cmp eax, 0xbd1e86ce
[*] in al, 0xf9
[*] loopne 0x555555554045
[*] mov esi, dword ptr [rsi + 0x4b]
[*] push 0x28692ae7
[*] call 0x5555290644a0
[*] xchg eax, ecx

[...]
```

Le shellcode retournant immédiatement, il est impossible qu'il puisse être valide. En effet pour rappel les **2 caractères dupliqués** dans rdi (*et rax au moment de l'appel)* ne vont être en rien altéré par le shellcode et à l'issue de celui-ci, la valeur présente dans rax *(qui n'a donc pas bougé)* ne peut pas représenter **3 octets différents** *(par exemple la première sortie codée en dur attendu est 751E22F6AFDC1D1Ah)*  

- SBB et ret

```
[*] sbb al, 0xb8
[*] ret
[*] or byte ptr [rdx + 0x636345c0], dh
[*] cmc
[*] test byte ptr [rax], dh
[*] or dword ptr [rcx - 0x4e], 0x96e67a9b
[*] sub bl, byte ptr [rcx + 0x34]
[*] add cl, dl
[*] and dword ptr [rax], 0xffffff9d

[...]
```

Ici pour les mêmes raisons qu'évoquer pour le cas précédent, la première instruction n'est pas suffisante pour obtenir les différentes valeurs attendues à la sortie du shellcode


- Le bon shellcode

Il ne restait qu'un seul shellcode, ayant le PIN **1203**: 

```
[*] movabs rax, 0x17385c21c8470c56
[*] xor rax, rdi
[*] push rbx
[*] movabs rbx, 0x31caaa5db0333fda
[*] xor rbx, rdi
[*] push rcx
[*] movabs rcx, 0xbf70117c0a477a5b
[*] xor rcx, rdi
[*] push rdx
[*] movabs rdx, 0x3e279f9775678f7a
[*] xor rdx, rdi
[*] push rsi
[*] movabs rsi, 0x247027417713ddbb
[*] xor rsi, rdi
[*] push r8
[*] movabs r8, 0xa5030df8f4a6505a

[...]
```

### Récupération du flag avec qiling


Maintenant que nous avons le bon shellcode il faut réussir à le résoudre pour retrouver les paramètres permettant d'obtenir les valeurs codées en dur. Le shellcode est plutôt très long et le passage sous `angr`[^3] n'a pas été fructueux durant le CTF. Cependant, une seconde caractéristique du binaire va nous permettre de rapidement retrouver le flag : le paramètre passé au shellcode ne dépend que de deux octets *(qui sont dupliqué pour remplir `rdi`)*. 

Nous avons donc 2^16 = 65536 possibilités pour chacune des sorties attendues. Nous pouvons réduire davantage cette range car nous savons que le flag commence par `MCTF{` ce qui donnera : `MC ; CT ; TF ; F{ ; {?` où `?` représente un caractère aléatoire. Si on utilise `string.printable` pour chaque cas il n'y a que **100 possibilités** ce qui peut largement être bruteforce. Voici le script qiling émulant le shellcode précédemment récupéré et affichant le flag : 

[^3]: https://github.com/angr/angr

```py
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.const import QL_ARCH, QL_OS
import string

flag = "M"
print(flag,end="",flush=True)

founded = False
def checkOutput(ql: Qiling,expected_rax: int) -> None:
  if expected_rax == ql.arch.regs.read("RAX") :
    global founded
    founded = True
  ql.emu_stop()

shellcode = bytes.fromhex("""666748b8560c47c8215c3817674831f8fff348bbda3f33b05daaca314a31fb67fff16648b95b7a470a7c1170bf664a31f967526648ba7a8f6775979f273e664831fafff66648bebbdd13774127702466674a33f767415049b85a50a6f4f80d03a566674c33c7415149b9f963db994456b3fb4c33cf6741526649ba7692701db3fab1ab66674c33d76741fff36649bbf9119dc8d2a35a75674e33df6667c1e10066d1e15166c7c12b5c6667422bd9678fc1c1cf0e664086f9666742fec2674e87c16742fff34080fed7420f45c3675b6742f7e666674208ca66674286df666742c0c3066742c1ca0d674232de67c1ce2067526667b2024032fa67428fc266422bfb675666674280faac0f49ce675e6733d8566742c6c6f5664002d68fc6f7e2672bc26703da42f6e0660fafc06742c1cf156642c1c007674209d3674286d7490fc867523cd7674e0f4ed267428fc266674002f9664e87db67420bcf53674280f91c66670f40fb428fc36649ffc1666748c1ee0056666742c6c67a422ad6428fc666420bf76703f142fff2ba1732ace06703f2678fc2664230c36753674280f911674c0f4dd367428fc3664bf7e0f7d6664bc1e00366674affca6667c1e0026642f7e366670bd1662bc2660fafd36742d1c266674ac1e2006742c1e201675766674280ff5b420f43df678fc76742c0e700674208f9660fafce6667480fafd26642c0c60166674bc1e80267c1e30329d766674803c16642ffc2f7e26640f6e7666742c1c3080fc966674a0fafd642ffc94232ce666740fece67420fafd342fff367b3f0664000de67428fc366490fcb664ac1e6006667c1e70266670fafd7666749c1ea04675066b0f066674032f8428fc067c1e30042fff2666742c6c24266674030d7675a666740c0e9016742c1c106664e2bd14ac1c02d67f7d74086de6642c1ee026733f86742fff34080fede66670f48cb67428fc36667ffca6640c0ea0167402ad3674ac1c10e666749c1e1026633c16667c1e7026742c1c11f6742c0eb016787f7d1e766674c09d166420faffa674c31c866674286f140f6d2666749ffc8ffc66667c1c000420bd6664bc1c33d4a29f2674209d3670fafd657c7c7ce88c20e6703f7675f6748ffc140f6d06740c0eb004bc1eb05666742f7e7c1e90066d1e366674c87cf66c1ea0066674e87d342fff042c6c05866674008c7678fc067c1e80067fff64280fb41664c0f4ade678fc642c0c7036649c1e808660fafce40c0c8056640f6d0666742c1c102674287d85642c7c64cce58d36703de675ec1cb130fcb670fce4b03d0fff167c7c16a97ac6d33d159666742c1e20066c1ee0267400af742ffc6660faffb6642c0c0066631cb0bfa6740fec76667f7e142c1cb076756666740c6c6df66674200f35e6667ffcf6648c1e702670fce52c7c2eaff52cf01d0675a42fff142c7c1636c0154674201ce596640d0c241fff04080fbc567490f45c8438fc00fafd666ffcb6640fec8420bfe67fff76748bfb5a36bba895fb30b66674803d75f67420faffe67fff366bb167e66674229da428fc34008c7666740feca6687fb31c6664bc1e00041504080f8254b0f43f0418fc066674ac1eb006748c1e802664008de67564080f98567420f4fce678fc666674086c642ffc24887ce6740c0c90467422bc8666742c1c70f42fff667bef551d53733d6678fc642fff066674280ff120f49f8678fc06667c1ca0867ffce0fcb66674b33f367420faff16701cf670fcaffc8420fafce67fff666674080fb716667420f46de67428fc643fff26749bad9a32648529b5f1966674b33fa67438fc26733d8664ac1ce07674933fb66420faffb666742c0ef00670fc86642c0cb066667420faffb4ac1c10f6642c1cf044c0bdf666748ffc866ffc6670fce664bc1c11166d1ef674b0faff1666742c1e9016753674280ff08664a0f47fb8fc367c1e80066420bc6674a31d60fcf66670bca674809f76667420fafc6664002fb6740c0c2036642c1e10166d1e666420fafce43fff3664280fa4666674d0f40d367415b6667d1e86742c0c10049c1c811674e2bcf66420bcb52664080f940660f4dfa675a43fff24080fa564d0f42ca438fc266420fafd6fff3664080f9a2664c0f4ecb428fc30fafd1664086df43fff0664080fbd6664b0f4fd8418fc066674201cb6742c1c71667fff14080ffb70f4ad167428fc16740fec966674a01f242c1ef036667c1ee026667f7d2666748c1cf1142c1e900fff0664080fa4c66670f4bd867428fc06687f242f7d267fff06640c6c0f9674008c767428fc06667ffc767d1e96742ffcb6742c0e90042fff3674280fe2867420f4fcb675b4ac1eb02fff1664280fe95670f4fd9428fc14b33c9674231f36640fec16742fff16748b9ba53f791588d993766482bf967428fc16640c0cf0166674209d96667d1e26648c1c31f664028d866420faff166672bd949ffc867415049b89a22593767833b7e492bc067438fc066c1c307666740d0e866674200cb664287dac1c80366674201da6742fff242c7c24988ddc92bc2678fc24209c3666731da67fff16740c6c1af67402ad159666742f7d0c1eb026642c0e0006742c0c10342c1c01642fff267ba5247fda14209d3428fc24c0fafcb67ffca6753674080ff2967420f42f3678fc3674af7d16740fecb66420faff66667c1c60b66674209f1664ac1c92167415366674280fb026667490f47cb438fc3666742c1c0066748c1e00757664280fb4b0f4cf7428fc7674d03d366c1ee0066674028ca6667c1e90142f6e04c87da6667c1c803c1c620664bc1ea02666742d1e942fff766674280fad7420f4dcf675f6667c1c10b4f0fafc16740c0c30442c1e700664287d1c1ce0966ffc9664c31c6674287fe42fff666673c85670f4fce428fc6664208f067420bc65740b70b6667422af7428fc76742c0c8086742fff66667c7c6a2bb66422bd65e4affcbfff1664280fbe466420f4bd167428fc1666742ffc142fff3664280fb4d664a0f42c35b6753b338664228da67428fc3670bc66742c1cb18666740c0c60240f6d266f7e066d1e36667c1c00d6667c1c005fff0664080fb4a670f45d8675842c1cb18670faff666c1ce036649ffca6642c0c90366674901c06748f7e26701ce42c1e00067490fafc9536642c6c3e2422afb8fc36742fecf4b0faff148c1c228666731d1c1c0136649f7e1664ac1c9124086f3674b0bdb664032c7670bfe666701c2666748c1c2366787f76740d0e366674ac1eb00492bc86649c1c9005342c7c3610b308167422bfb67428fc36742f7d6674c0fafdb6603fe41fff3666749bb9329e8eb45bccfcd664f01d967438fc34ac1ef070bfa42ffc6664a2bde6642f7e766674203f0420bd966674b0faff9664a0faff867fff0664080fee5660f44f8584231d867f7e3664bc1eb04670fc967480bf242c1ee0042c1ee0043fff06649b899e09514162fded8664d33d8674158fff3b3bf674232cb428fc3675642c7c6cdad9f7a29f1428fc66648c1c83066674a01f16642f6d656666740b62866674208f35e6733cb67fff7666748bf66a145e4a5e45fca664b09f8428fc76749f7d0666731d6674150674080f87e490f41f0438fc042c1c01066422ac166422bc36667490fafc36667480fc967c1c919664bc1c13b4b87c3490fafd26640c0ee006701ca6640c0ca06674232df57666742c6c7aa4230fb675f6742fff2674280fef1420f4ff28fc26667c1cf0cc1e6036642c1c60a4028f35266674080fffb670f4eca67428fc26640c0e8006640feca0fafde670fafc3674233fb666748c1e70766674f0bc34150674280fa81674f0f4dd067415867fff2664280f89467420f49c267428fc2f7e7675166674280fff7674a0f4cd167428fc142c1e90352674280fafc664c0f46c267428fc26752674280fab0420f48c25a6742c1c01f6752c7c29a6637a26733ca678fc26742c1eb044c31d249f7d34287d642fecf66674287da4f87d06742fff6c7c66ba08c156703ce5e42ffc9fff14280fb94420f4dd18fc1666703f1664ac1ea076787d942ffc042d1e641fff2674280f907490f40da415a6742c1ea006742c1c1026742c0e600674b03db4e31df66420fafca664bc1e90466f7d766674af7d76742fec66642c1e102664286d36742c0e100c1e802fff24280fbe667420f49ca428fc266c1cf0f674987f066c1c90b5666674080fbbd66420f4dc6675e66ffc9664ac1c3366667422af96642c1ce046740fec266420fafc24228c342c1e8006740c0e80066c1c910f7e266674287c76742c0c007660faffb87de6740c0c60266674209d86687dff7e166420fafd96640c0e300666740fec86742fff36642c6c3756667402af3675b674bc1c20867fff366674080facc660f4ed367428fc367c1c30b56666740c6c6dd66674200f367428fc66740fec66640f6d267c1e103675667bec3f075e6420bce675e40fec06740d0e06640c0c30442c1cf106740c0e2014201f96740c0c00466420afb6642c1e802664bc1e8064c0fafc1666742f7d2666742c1e1026742c1ca1a66674229ce42fff0674080fb7866420f49f8428fc067490fc84152664280ffff66490f43fa418fc20bc340fec86742fec867fff766674280f8d567420f4fcf428fc7664286c6564280ff21660f4bc68fc66742d0ee41fff2674080faa9664b0f47da67418fc24200f26742fff0674280fb0e66420f46c88fc066ffc9666740fecb6787d367fff6674080fe3b670f4cc6428fc6666748c1e7076642c0c20567c1c808fff7674280feec674e0f4fd78fc756674080f9bb66420f4dc6678fc642fff1674080fe8567420f46f9428fc14229c1480fca674affcb666731c2666742c1c7016742fff1666742c7c1e7ab6667420bf1596667c1cb0766420fafd26742fff366674280fef14e0f40d38fc366674209fbfff266674080f89766670f49da67428fc25067b8986bbf2b4229c767586751664280feb967420f41d1678fc16729df6642f7e26742c1ea0266672bd86648c1e8014bffc90faffb674bc1e00142fec65666674280f9df660f4ec6678fc66742fec96642d0e767fff24280f8a9420f41da8fc2674affcb4b87d3664ad1eb6748c1e60342f6d36742fff36642c6c3094232f3678fc3664b0bc86667c1ce086787dffff666674280fa5e4c0f41de5e6642c1e3004bc1e304674bc1c33f6667ffcf666742d1e36640f6d76642ffc8666742c1c00467d1e86687c266480fce6640c0e1016633d3675767bf104a4e3d670bf767428fc766d1ef42fff74280fa42420f40d78fc766674287d341fff0674280fa616667490f4ac8415809c26703ca6642fec1674c87d266f7d36640d0eb660fafd7666749ffc8674233fe67fff766674280f9d36667420f46d7675f6667480fcf52664080fa3a67420f4dda67428fc2664c0fafc86648c1ca36666749c1e2006642c1c6066742f7e3674887ce6742fec1666742c1c110674bc1e2046742fff1664280fa5067420f4cf167596667f7d366674a03cf6687d367ffc366674bc1c836ffc16642c0e2006742ffc66749c1ea056642c1ce079242c1ef004e0fafd766670faffe0fca48c1cb1b42fec0664000d86742f7d342c0c7016642c0e700576640b7c1674202d75f666742c1ca076667420fafdb67c1cb1167524280ff1f0f4fda5a664200c36648f7d349c1e808c1cf1a6667f7e3674231d6fff366c7c312ba66674209d85b67420fafff666787f966674286d76667420fafd642f6e16667c1e9006749c1c3106742fff06648b804cc874a7b8781b2674c33c0428fc066c1eb026740f6d3666742ffcf6742fff667c7c69ed65d2303c65e67ffce6667ffc7666740c0c805666742c0c9066742c0c00842c1ef026742ffc06742f7d2666742c0c00342c0e800664209d0674ac1e905666740c0eb004086fa670fce42c1ca1640d0cf664801df666748c1c11d67fff1674080ff00480f4dc167428fc142f6e3664e2bd966674229ca6748926729f167533c3a0f47f38fc367fff342c6c3124228d9428fc366674831f84286df48934ac1e604674286d76742fecf6640c0ee006667c1ee0066670faff66703fb6648c1e1026751674080fa2866670f4cc1678fc15148b985d6f798f861a5f1664c0bc18fc16642d1c0480faffb674ac1e60567f7d6666749c1e9046667402af366400ace670fca664228c166420fafc24b03da42f7e26640d0eb66c1c71042c1c11d666740c0c105516648b94d51ac4bf5d6591266674829cb67428fc1f7e6664c0bc966420faffac1cb036667c1c2020fafc249d1eb66674887f1fff266674080f9ec66420f4df28fc242ffc066c1cf03666742f7e1664200de6642fec866ffc06740c0c2046642c1cb0d6642c1ce086742c1e00266670faff043fff2664080fb1d674b0f40fa418fc2674b0fafc8664286fb6667ffc84af7d36742ffcf42d1e7674286df67ffc26742c0c300666742c1c9006742fff6666748bee6e6f69577111d5367482bfe675e6640c0c60540d0e16640c0c202d1e1674a87d76742ffce2bd96642d0ea670fcb6629d142c0ee0166ffcb480fafda66674032d6666740f6e141fff26749ba05dd54411060533467490bf267415a666742c1c2096667d1e6674229c666674bc1e10152664280fa9d66670f43ca675a40d0e70fafd2664229f3664bc1c01166674286c2674bc1e80249f7e1666740c0e6006742fff74080fb8166420f47df675f6640c0e100ffc9664ac1c905664ac1ef0642c0c20567420fafc26667c1e002674bc1e004666740c0ef0066674032de4286d967fff0c7c05bd8de0d670bd0678fc066674233d742fff3c7c350ec5a8e674201da5b66670fafd0664b01db66674086c342c0e200674e09c9fff16740c6c13e674030c859420faff66751664080ff9b6667420f4af9596642c1eb006753664280fe18670f4dd3675b6667c1ee024933d16667f7d3674c31c66667422bf16742fff0664080f8d867420f4fc8428fc06743fff2674080fb174f0f49ca67418fc26756c7c6111ef9cf67422bfe678fc666670fafd16640c0c706666748c1c2206667926742f7e366674ac1e3076740f6d6666742c1e20166480fc96742fff2663c4166420f4bda67428fc242f6e242fff066b88009664233d0678fc0674287cf674931c8674a0bc8670fafce660fafc366674ad1e66667480fafd36740f6e2674c0fafc348c1e8044286c666420faff966480fce674a0fafdec1c01166674a29d10fca6742c1e8006742f7e167ffc1674c87c866674233c2674c87c8402ad7674209d942fff266674080fa52670f44ca678fc2666742ffc2664287f941514280fed54f0f46d9415967c1e103fff766674280fe5c670f41cf428fc766674bc1c13866c1cb10674ac1ca3d67f7e2666748c1eb0466c1e3006667420fafde5066674280f888420f45f05803fb666740fecb675266674080fb4c6667420f4dfa428fc26640fec167c1e900666733c666674030da660fafc366420fafc0666740c0c20140c0c804666742f7d66748c1c9046742fff342c7c353ff7e864201de8fc36667ffc6664201d16753664080f9e5660f45c3675bc1c20a6667422bd066674202fb516742c6c12e66674002f9428fc1674287d15266ba2fd1664209d15a674233f9672bd966674000fe5667bec61936166709f08fc653664280fa7967420f42c3675b6667c1ca10674150664280f83f67490f42d0438fc066674887cb6642c1ef016642f7d66703f742c1e90242c0e60143fff2664280fa6467490f4cfa67415a4af7e7664201cf666742c1eb0266674203d8422ac1674002d6420aca6742fff067c7c0caabd8fc4201c658c1ea0142c1c3046742c1cf0c664229ce6742fff1674080ff9e420f4ed9675942fff74280fa760f41d75fc1e7036648ffc0f7d26750664080fe8f664c0f4cd067428fc066ffc966480fca6742c1c002660fafd966670fafc06742ffc3674287c766480fcb670fce4150674280fff46667490f42c067438fc06609fb4ac1e70487c1666748c1c13e0fafff6667c1e3026740c0ef016740c0ce006648c1e90867fff666674280fb1b670f44ce8fc666674ac1eb01506640c6c0c34232d8678fc0420fafdb670fcb67fff367bbbf5fb26729de67428fc36649c1ca24666749ffc96648c1c9206742fece664228f866f7d1ffc76642ffc00fc96667f7e74829f06640d0e301f048c1e6056642c1e90067504080fb966667420f4ed06758666742ffc74987f0c1e90366c1e702666742c1c804664287d66742c1c7186748c1c33666d1e94b0fafc96756666742c7c6f402666729f35e6609fb66674831f366674287d06667420bc766674ac1c8046751c7c1fbc6b666420bd1428fc142c1c302670fafca6640c0ca05674287d9674ac1e107666740fecf674201fe66d1e242fff0666742c7c0221b6601c367586640c0c2044232d36640c0ee0153664080f9880f46d3675b67c1c91b666742ffcf67fff266ba614066674233c2678fc26667402ac367480fafdb6742fff042c7c0e76ee657674229c167428fc06640f6e76740fec741fff0674280fae44d0f43c8438fc0666742c1e7004ac1e702c1cb13420fafc666420fafd06667480faff966674229d648c1e0086687cfc1c61e664affc14b01f2666742c1e602674bf7d26640c0e60066674b29c0420fafdb674287d7420faff8666740c0c00267fff766bf90ba6603c7675f4208cb666742c0e7006642c1c00542f7d166674203d166674230df6642d0ea6742fff7664080ff44480f4cf75f42c1eb00566640b6c6674030f1678fc6666742c0c702fff14280feb266420f42f967428fc16709cf670faff042ffc8674a03cf42fff16642c6c1104202d1678fc1664229c84287f96742f6e26667490fcb674b29c36642c1ea006742c1c10b42ffc142f7e066674233c1674c0fafc8664e0fafd366674ac1ef034e87db6667420fafc34287f1664ac1c83b67420bcb66670faff040c0c80201d96742fff04080fa9b674c0f4ac0428fc0666748c1c23967fff1674280f81e674e0f4fd967428fc166400af1666740f6e766674230fbfff0674080f8f8420f44f0428fc06649c1c81d67c1e2006640d0e757666740c6c7fc4030fe428fc7c1ef046648d1e8666740fec2fff36742c6c3b066674002cb428fc340c0cb016640c0c7086642c1eb006731de664008fe6642ffc66743fff3664080f96f66674b0f45f3415b6667c1c6036667422acf66c1c70067fff24280fb0566480f4dfa675a674287ce664bc1e802664202d34ac1ef07674286ca42ffc86640f6e167422bd9666748c1e2086642f7d366480faff7666742ffc76667480bce49c1c8126740c0ef0166422bda6648ffc84a0fafd36742fff2664080f97067420f49da8fc266674201da674201da66c1e00142ffcb6742fff240c6c293674230d067428fc242c0c905666742c1e10048c1c9386740c0ea00fff66742c7c6909c7408422bc65e674231cbc1c318664008da6742fff1674080f9ab420f4cd18fc16787c7664287d3660fafd867fff766674280fe8d66420f43d7678fc76642f6e149c1c1376642fecefff142c6c13166674228c8428fc16742fff266674080f82b670f4aca675a42c0e7004028d36667490fc967f7e06740c0c00653bb07c72db4674229da67428fc341fff04080f8a166490f44c067438fc066c1c110420faff3666742c0ca00674a0fafc066670fafdf664bffcb666742ffcb674903d2666733f2666748c1c61e67c1e302664086da674ac1c72f67480fcf6742ffc8664287d66667c1e10066674ac1e808670fc967400ad7666742c1c20a6642c1e701670fca670fafc242c1c212660fafc748c1ea066742fff76667bf49cd66420bcf8fc7664086da01d1664ac1c90d666703d76740c0cb066687c16667420fafce42c0c80552666742c6c23e6667402aca675ac1e90166674233f8666742c1e8026751674280fb3866670f47f9678fc1fff042c6c0c9664202f0428fc066420fafce5766674080fe43420f44f7428fc766674bf7d2664affc066670fafd65166b96b6f66674203d1675942f7d1674ac1e802666787c267fff766674080f80067420f46d767428fc7c1c91243fff066674080fb554f0f49d841585367b3136667402af3678fc36642c1c1046742c1e00242fff366674080feba67420f46fb5b67c1e1026640fec3664bf7e36642d1e167d1e26642c0ce03674ac1c333674287d9670fcefff3674280fffc6667420f4bf3428fc3fff2674280fbdd674a0f4fca8fc2664affc240d0ce6648c1ce0a6787c36749f7e26642c1c70c6742c0e3006640d0ef6642c1e702c1ca1a4286c35267ba1e20d67603ca5a2bf342c1ea036740c0e600666742f6e131d66742fff3666742c6c367674002cb67428fc3674008d367480fcb6787ce6742fff6674280ff00674a0f4dfe678fc64e0bc66687df6649c1e20142fff1c7c1dcbe3aa26733f15967fff06667b80b2a6667422bf88fc0660bfb6742c1cb1d66c1e0024228f76649c1ea0866c1c9004b0bfb666742c1e1026740fec2fff0666742c6c04366674008c2678fc048c1c814664a31d966674af7d04ac1ca36666742c1e10242c1c20466674a0bda664209c6f7d3666740fec967fff24080f9210f4bfa675a504080fe4c420f40f8428fc0674287c166674ac1c8286740fec3660fafc942c1ca1f66422ada66674231de42fff367bb380ae8a14201de675b6748c1c81f6642d1e0664ac1c32c6742fff24080ff7a6667480f49da428fc2674c0fafd366674032cf42fff26667ba0fc9666729d35a674286ca674c09c966672bc25366674280ff6667420f41cb67428fc36667400ad76742f7e74287d66787ca666740f6e142f7d2664231ca66420fafda6667c1ce066687c742c0ea006648c1ee046742c0e0006642c0c6004233fa6742fff64280fa0e420f45c667428fc666420fafc042d0eb666701da6743fff149b95fdb414a353de23566674d09cb438fc1664086d966674203da42c1e901fff26667c7c2aad366670bfa8fc267c1c602666748c1c9136642c1e000660fafc367480fc966490fafd86740fec7fff366674080f85a480f47c3678fc367490fca66674201f042fff166674280f902420f46d1678fc1666749c1e2036667c1ce0b4287d16742fff36667c7c3c954666703fb8fc3666742d0e866420bde666742f7d2666742f7e26667c1c70267420faff9666742c1c10540d0e04287d36642c1c9094229ce6642c1eb00666742c1ea0257674080fb6466420f4acf428fc76642c1cb05f7d266ffc36742fff1674080ffcd67420f43d167428fc16667400ac1fff1664080fe7566420f42f98fc167514280f963480f4ad967428fc140c0cb07675267ba64fc6fe56733ca5a6667c1cf10666740fec942c1e803674209d34287d066674ac1eb064b0faffa67fff066c7c065e366674203f067586740d0e66742fff3674080fb67420f4ef3428fc340c0e30067480fafc642c1cf0e4a0fafd231fb6642ffc9674c33d16740fec342ffc866670faff366ffc86642c1e601415066674080fbc7664f0f43d067438fc06667f7e642f7d7674bc1c106420faffe6742c1c2006640f6e3526740c6c268674228d3428fc242c1c90366674ac1e703674002cffff1664280fbeb66480f43c167428fc1934bf7e26667c1e700666740c0c00767fff766c7c794f8664203c78fc742f7d26687f742c1e10142d0e842c1ce0f664008df6667c1e70267566642c6c612664008f767428fc6674987fa6742c0ca056667c1c102c1e1046740d0eb6742c1cb05664ac1ea0466c1c30c6667c1e3014a87d848c1c23d664d2bc266674e87de6742c0c3016667420faff366480fc8c1e00153664280ff35660f4ff3678fc340d0e1664086ce67c1e600fff6674280f85e6667420f4fde67428fc66649c1e30740c0e200c1ef006667f7e26742c1cb18c1e202666749c1e805664f03c36667ffc6664b03d96667d1e16757663cef0f49c767428fc74c03defff34280f9670f4ccb8fc3666742c1ef02674030c767480fafdb6649ffc06667c1c60bfff24080ffd166674e0f4ac2428fc267480fc9664008c242c0ce0066674a01cec1c10766674287f142c1c32066674affc087ce66674008fb664bffca6742c1c31c67c1e90467480fc9566742c7c6a8f9ecdd67422bfe678fc6666749f7d2670fafd14a0fafd7666787de6642f6d0ffc967420fafc242fec06648c1e805fff042c7c0f462ab9a01c78fc02bd149f7e1675048b85e912d0c719972bb4a09c7678fc0674008cb0fcb66c1c60c67c1ee046649f7d06648ffc74086f24f87c36742f6e76756674080fedb480f4cde675e6642f7e367f7d667fff3666748bbf6d894e26ba27439674c2bc3675b4229d94287d16642c1e000674bc1ea0642c1eb03670fcf6741516749b9492e0ce64c85772466674e29cf418fc15166c7c18e0966674201cf6759480fc987c2666742ffc866674286f9fff64080fbd6420f4ad6678fc642c1c112660faff666c1cb0c67c1c910664287cb66674209f26742c1c8066642c0cb0641fff24280f94967490f47d2418fc266c1c710c1ea0066674229cb42c0c30666c1ee006648c1ca0966670fafc16601ca66674a31d8674a33c14831d066674831f0664833c7664b33c04c31c8674b33c24933c367438fc367438fc2438fc167418fc05e428fc267595bc3""")

rootfs = r'/qiling/rootfs/x8664_linux_glibc2.39/'

hardcoded_results = [0x751E22F6AFDC1D1A,0x25E2D8737E1EE778,0x5FA5062A2A463E93,0x31E402F96E8BDF97,0x835BE6989055C8F7,0x5D96E686BBBB53FA,0x0ECE6FF58CDD9D31A,0x0C21A2CBC37DBC25F,0x504E496158267321,0x1E7F1D0186F1EC8C,0x177A0713EE72684C,0x701183528F5AC6CF,0x0B732A1AFDC2F5679,0x76C06994CE3A61BC,0x0F5F06AB9884DE54F,0x701183528F5AC6CF,0x5A37ADF157A8C201,0x0C094D5287D091C4F,0x0F5F06AB9884DE54F,0x3DAA050C3B50450E,0x0A93C0AF6A0E9C41C,0x0F5D4CBAB3B2C88A3,0x0A27A01B298EC17A8,0x5FCEFDDD776A26F0,0x0DEBDE5DBB1C1C4B3,0x0E08C572F24190AB,0x0D512D32829E4869,0x0FFBD122F4A434777]

for expected_rax_output in hardcoded_results:
  for c in string.printable:
    ql = Qiling(code=shellcode, rootfs=rootfs, archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.DISABLED)
    rdi = ( hex(ord(c))[2:] + hex(ord(flag[-1]))[2:] )*4
    ql.arch.regs.write("RDI", int(rdi,16))
    ql.hook_address(checkOutput, 0x000000000120137f,expected_rax_output)
    ql.run(end=0x20137e)
    global fouded
    if founded:
      print(c,end="",flush=True)
      flag+=c
      founded = False
print()
```


**MCTF{ShUff13_th3_sh3LLc0de!!}**
