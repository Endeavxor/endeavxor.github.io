---
title: "[RE] VM : Vivat Mathematica | InterIUT 2024"
description: "Writeup du challenge 'VM : Vivat Mathematica' lors du CTF InterIUT 2024"
publishDate: "01 June 2024"
tags: ["reverse","qiling","z3","CTF","maths"]
draft: false
coverImage:
  src: "./cover.jpeg"
  alt: ""
---


## Description
- CTF : https://x.com/CTF_Inter_IUT/
- Challmaker : Endeavxor
- Difficulté : Difficile
- Nombre de résolution : 0 :(

*N.B. La clé de voûte du challenge est grandement inspirée du challenge de `face0xff` lors des qualifications à l'European Cyber Week 2023 nommé `kaleidoscope`, dont vous trouverez le WU ici : https://blog.thalium.re/posts/ecw-2023-kaleidoscope-write-up/ , ainsi que les sources ici : https://github.com/face0xff/kaleidoscope*

## Prise d'information

```sh
endeavxor@deb:~/InterIUT2024/VM : Vivat Mathematica$ file unknown

unknown: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0a8196d947be91d1a82868331326c0736afdcab7, for GNU/Linux 3.2.0, stripped
```

Rien d'exotique à priori, un ELF 64 bits strippé.

```sh
endeavxor@deb:~/InterIUT2024/VM : Vivat Mathematica$ strings unknown

Erreur: Pile pleine.
Erreur: Pile vide.
Erreur: Index invalide.
Erreur: Pas assez d'
ments sur la pile
Erreur: On ne divise jamais par 0 !!!
Bravo !
Erreur: Opcode non reconnu (%02X).
data.dat
Erreur lors de l'ouverture du fichier data.dat
Erreur lors de l'allocation de m
```

Confirmation qu'il s'agit potentiellement d'une mini-machine virtuelle avec utilisation d'une pile, en somme une machine à pile avec des instructions/opcodes personnalisées.


## Reverse statique

*J'ai retypé et renommé une légère partie pour faciliter la lecture du writeup.*

### main

```c
__int64 __fastcall main(int argc, char **argv, char **a3)
{
  char *ptr; // [rsp+8h] [rbp-18h]
  size_t size; // [rsp+10h] [rbp-10h]
  FILE *bytescode; // [rsp+18h] [rbp-8h]

  bytescode = fopen("data.dat", "rb");
  if ( bytescode )
  {
    fseek(bytescode, 0LL, 2);
    size = ftell(bytescode);
    fseek(bytescode, 0LL, 0);
    ptr = (char *)malloc(size);
    if ( ptr )
    {
      fread(ptr, 1uLL, size, bytescode);
      fclose(bytescode);
      run_mini_vm(ptr, size);
      free(ptr);
      return 0LL;
    }
    else
    {
      perror(aErreurLorsDeLA);
      fclose(bytescode);
      return 1LL;
    }
  }
  else
  {
    perror("Erreur lors de l'ouverture du fichier data.dat");
    return 1LL;
  }
}
```

La fonction `main` ouvre le second fichier fourni `data.dat` et lit son contenu dans un buffer. Ensuite, elle appelle la fonction `run_mini_vm` avec le buffer et sa taille, qui sera le cœur du challenge.


### run_mini_vm


Sans renommage/retypage le code pseudo décompilé par IDA[^1] se présente comme suit : 

[^1]: https://hex-rays.com/ida-free/
```c
size_t __fastcall run_mini_vm(char *bufferOpcodes, size_t totalSizeBuffer)
{
  int v2; // eax
  size_t result; // rax
  char v4[412]; // [rsp+10h] [rbp-1B0h] BYREF
  int v5; // [rsp+1ACh] [rbp-14h]
  unsigned int v6; // [rsp+1B0h] [rbp-10h]
  size_t i; // [rsp+1B8h] [rbp-8h]

  sub_11E9((__int64)v4);
  for ( i = 0LL; ; ++i )
  {
    result = i;
    if ( i >= totalSizeBuffer )
      break;
    v2 = bufferOpcodes[i];
    if ( v2 <= 11 )
    {
      if ( v2 > 0 )
      {
        switch ( bufferOpcodes[i] )
        {
          case 1:
            sub_133E(v4);
            continue;
          case 2:
            sub_13AE(v4);
            continue;
          case 3:
            sub_1422(v4);
            continue;
          case 4:
            sub_1492(v4);
            continue;
          case 5:
            sub_1502(v4);
            continue;
          case 6:
            sub_1604(v4);
            continue;
          case 7:
            sub_1313(v4);
            continue;
          case 8:
            sub_1202(v4, (unsigned int)bufferOpcodes[++i]);
            continue;
          case 9:
            sub_126E(v4);
            continue;
          case 10:
            sub_1572(v4);
            continue;
          case 11:
            v6 = bufferOpcodes[++i];
            v5 = sub_12C5(v4, v6);
            sub_1202(v4, (unsigned int)(char)v5);
            continue;
          default:
            break;
        }
      }
LABEL_21:
      printf("Erreur: Opcode non reconnu (%02X).\n", (unsigned int)bufferOpcodes[i]);
      exit(1);
    }
    if ( v2 != 127 )
      goto LABEL_21;
    if ( (unsigned int)sub_126E(v4) )
      puts("Nop");
    else
      puts("Bravo !");
  }
  return result;
}
```

On comprend vaguement que le contenu du second fichier est parcouru et qu'en fonction des octets qui s'y trouvent, différentes fonctions peuvent être appelée. Une analyse plus approfondie sur ces fonctions est nécessaire, mais l'on peut déjà faire l'hypothèse que les octets représentent différentes instructions/opcodes.

### sub_11E9(v4)

```c
__int64 __fastcall sub_11E9(__int64 mini_vm_state)
{
  __int64 result; // rax

  result = mini_vm_state;
  *(_DWORD *)(mini_vm_state + 400) = -1;
  return result;
}
```

Cette fonction est pour le moins assez cryptique, elle assigne `-1` à un offset `400` depuis une variable présente sur la stack. Il s'agit probablement d'une structure. Notons ici que le paramètre passé à la fonction est aussi passé à chacune des sous-fonctions dans le `switch case` de `run_mini_vm` , il pourrait donc correspondre à l'état de la mini machine virtuelle sans pour autant pouvoir définir pour le moment sa structure complète.


###  Les autres fonctions

Les premières fonctions dépendantes des opcodes révèlent plusieurs informations :

`sub_133E`
```c
__int64 __fastcall sub_133E(__int64 mini_vm_state)
{
  char v2; // [rsp+18h] [rbp-8h]
  char v3; // [rsp+1Ch] [rbp-4h]

  if ( *(int *)(mini_vm_state + 400) <= 0 )
  {
    puts(aErreurPasAssez); // Erreur: Pas assez d'éléments sur la pile\n
    exit(1);
  }
  v3 = sub_126E(mini_vm_state);
  v2 = sub_126E(mini_vm_state);
  return sub_1202(mini_vm_state, (unsigned int)(char)(v3 + v2));
}
```

`sub_13AE`
```c
__int64 __fastcall sub_13AE(__int64 mini_vm_state)
{
  char v2; // [rsp+18h] [rbp-8h]
  char v3; // [rsp+1Ch] [rbp-4h]

  if ( *(int *)(mini_vm_state + 400) <= 0 )
  {
    puts(aErreurPasAssez); // Erreur: Pas assez d'éléments sur la pile\n
    exit(1);
  }
  v3 = sub_126E(mini_vm_state);
  v2 = sub_126E(mini_vm_state);
  return sub_1202(mini_vm_state, (unsigned int)(char)(v2 - v3));
}
```

`sub_1422`
```c
__int64 __fastcall sub_1422(__int64 mini_vm_state)
{
  char v2; // [rsp+18h] [rbp-8h]
  char v3; // [rsp+1Ch] [rbp-4h]

  if ( *(int *)(mini_vm_state + 400) <= 0 )
  {
    puts(aErreurPasAssez); // Erreur: Pas assez d'éléments sur la pile\n
    exit(1);
  }
  v3 = sub_126E(mini_vm_state);
  v2 = sub_126E(mini_vm_state);
  return sub_1202(mini_vm_state, (unsigned int)(char)(v3 ^ v2));
}
```

`sub_1492`
```c
__int64 __fastcall sub_1492(__int64 mini_vm_state)
{
  char v2; // [rsp+18h] [rbp-8h]
  char v3; // [rsp+1Ch] [rbp-4h]

  if ( *(int *)(mini_vm_state + 400) <= 0 )
  {
    puts(aErreurPasAssez);
    exit(1);
  }
  v3 = sub_126E(mini_vm_state);
  v2 = sub_126E(mini_vm_state);
  return sub_1202(mini_vm_state, (unsigned int)(char)(v3 | v2));
}
```


Un pattern commun est observable avec comme unique variation l'opération effectuée au niveau de la dernière fonction. De plus, la première fonction cryptique prend un peu plus de sens avec le message d'erreur `Erreur: Pas assez d'éléments sur la pile\n` si l'offset est inférieur ou égal à 0. L'offset avait été initialement mis à `-1` , il s'agirait donc d'un pointeur sur le haut de la pile. Qui dit pile dit arguments dans la pile, et l'opération semble être effectuée sur deux éléments provenant de la fonction `sub_126E`: 

`sub_126E`
```c
__int64 __fastcall sub_126E(__int64 mini_vm_state)
{
  int pointerStackIndex; // eax

  if ( *(int *)(mini_vm_state + 400) < 0 )
  {
    puts("Erreur: Pile vide.");
    exit(1);
  }
  pointerStackIndex = *(_DWORD *)(mini_vm_state + 400);
  *(_DWORD *)(mini_vm_state + 400) = pointerStackIndex - 1;
  return *(unsigned int *)(mini_vm_state + 4LL * pointerStackIndex);
}
```


On constate une fois de plus l'offset utilisé pour vérifier si la pile est vide, et qu'un autre offset est défini lui aussi pour renvoyer une valeur qui semble être sur 4 octets *(possiblement int/unsigned int)*. La structure de `mini_vm_state` commence à se dessiner :

```c
typedef struct {
    int stack[100];
    int sp; // Pointeur de pile
} mini_vm_state;
```

On peut donc la définir et renommer cette fonction pour mieux comprendre : 


```c
__int64 __fastcall vm_pop(mini_vm_state *mini_vm_state)
{
  int pointerStackIndex; // eax

  if ( mini_vm_state->sp < 0 )
  {
    puts("Erreur: Pile vide.");
    exit(1);
  }
  pointerStackIndex = mini_vm_state->sp;
  mini_vm_state->sp = pointerStackIndex - 1;
  return (unsigned int)mini_vm_state->stack[pointerStackIndex];
}
```

Cette fonction va donc tout simplement récupérer l'élément sur le haut de la pile. En revenant sur la fonction `sub_133E` vu plus haut et en renommant on comprend mieux la logique derrière le début du pattern : 

```c
__int64 __fastcall vm_add(mini_vm_state *mini_vm_state)
{
  char v2; // [rsp+18h] [rbp-8h]
  char v3; // [rsp+1Ch] [rbp-4h]

  if ( mini_vm_state->sp <= 0 )
  {
    puts(aErreurPasAssez);
    exit(1);
  }
  v3 = vm_pop(mini_vm_state);
  v2 = vm_pop(mini_vm_state);
  return sub_1202(mini_vm_state, (unsigned int)(char)(v3 + v2));
}
```

Il nous reste à identifier la fonction `sub_1202`, qui va simplement mettre sur le haut de la pile la valeur qui lui est passée en paramètre :

`sub_1202`
```c
mini_vm_state *__fastcall vm_push(mini_vm_state *mini_vm_state, char valueToPush)
{
  mini_vm_state *result; // rax

  if ( mini_vm_state->sp > 98 )
  {
    puts("Erreur: Pile pleine.");
    exit(1);
  }
  ++mini_vm_state->sp;
  result = mini_vm_state;
  mini_vm_state->stack[mini_vm_state->sp] = valueToPush;
  return result;
}
```

Le résultat des opérations sera donc mis sur la pile. On peut renommer les fonctions similaires dans `run_mini_vm`. On y voit un peu plus clair : 

```c
switch ( bufferOpcodes[i] ){
          case 1:
            vm_add(&mini_vm_state);
            continue;
          case 2:
            vm_sub(&mini_vm_state);
            continue;
          case 3:
            vm_xor(&mini_vm_state);
            continue;
          case 4:
            vm_or(&mini_vm_state);
            continue;
          case 5:
            vm_and(&mini_vm_state);
            continue;
          case 6:
            vm_equal(&mini_vm_state);
            continue;
          case 7:
            sub_1313(&mini_vm_state);
            continue;
          case 8:                               // push next buffer byte on stack
            vm_push(&mini_vm_state, bufferOpcodes[++i]);
            continue;
          case 9:
            vm_pop(&mini_vm_state);
            continue;
          case 10:
            vm_modulo(&mini_vm_state);
            continue;
          case 11:
            v6 = bufferOpcodes[++i];
            v5 = sub_12C5(&mini_vm_state, v6);
            vm_push(&mini_vm_state, v5);
            continue;
          default:
            break;
}
```


Deux fonctions restent à analyser : 

`sub_1313`

```c
mini_vm_state *__fastcall sub_1313(mini_vm_state *a1)
{
  char v2; // [rsp+1Ch] [rbp-4h]

  v2 = getchar();
  return vm_push(a1, v2);
}
```


Cette fonction va simplement récupérer via l'entrée utilisateur un caractère et le mettre sur la pile *(afin de pouvoir faire des opérations sur l'entrée utilisateur par la suite)*.


`sub_12C5`

```c
__int64 __fastcall getFromStack(mini_vm_state *mini_vm_state, int index)
{
  if ( index < 0 || index > mini_vm_state->sp )
  {
    puts("Erreur: Index invalide.");
    exit(1);
  }
  return (unsigned int)mini_vm_state->stack[index];
}
```

Récupère le i-ème élément sur la pile.



Une fois le fichier `data.dat` parcourus en entier, le code vérifiant si nous avons le bon flag est le suivant : 

```c
if ( (unsigned int)vm_pop(&mini_vm_state) )
      puts("Nop");
    else
      puts("Bravo !");
```

En somme, l'élément sur le haut de la pile devra être égal à 0.


### Résumé de l'analyse statique


Voici une vision macro du comportement du binaire : 

- Une machine à pile est initialisée pouvant contenir 100 éléments et ayant un pointeur sur le haut de sa pile
- Un fichier `data.dat` est parsé et en fonction des octets qui s'y trouvent différentes instructions/opcodes sont exécutés en mettant le résultat de l'opération sur le haut de la pile.
- Ces instructions sont majoritairement des opérations arithmétiques simples
- Une des instructions permet de récupérer caractère par caractère une entrée utilisateur en les mettant dans la pile.
- Une fois `data.dat` parsé, on vérifie que le dernier résultat mis sur la pile est bien 0, auquel cas le flag est bon.

Nous avons donc 2 possibilités pour résoudre cette mini-vm

- Réaliser un parseur statique des opcodes pour reconstituer la logique derrière `data.dat` au sein de la VM.

- Instrumenter dynamiquement le binaire pour afficher les opérations effectuées lors de son exécution.

Je vais opter pour la seconde qui est plus rapide bien que moins précise sur la compréhension exacte du fonctionnement de la mini-vm.

## Résolution

### Récupération de la logique d'exécution de la mini-vm avec qiling

Pour cela, je vais utiliser `qiling`[^2], qui va nous permettre d'émuler et d'instrumenter le binaire. L'idée va être dans chaque fonction du `switch case` de logger l'opération qui est effectuée et les valeurs via des `hook`[^3].

[^2]: https://github.com/qilingframework/qiling
[^3]: https://docs.qiling.io/en/latest/hook/

```py
from qiling import Qiling
from qiling.const import QL_VERBOSE

rootfs = r'/qiling/rootfs/x8664_linux_glibc2.39/'
ql = Qiling(["./unknown",], rootfs, verbose=QL_VERBOSE.DISABLED)


def vm_add_hook(ql: Qiling) -> None:
    eax = ql.arch.regs.read("EAX")
    edx = ql.arch.regs.read("EDX")
    print(eax,"+",edx, "// DEBUG RESULT:", eax+edx)

def vm_sub_hook(ql: Qiling) -> None:
    eax = ql.arch.regs.read("EAX")
    ecx = ql.arch.regs.read("ECX")
    print(eax,"-",ecx, "// DEBUG RESULT OPERATION :", eax-ecx)

def vm_xor_hook(ql: Qiling) -> None:
    eax = ql.arch.regs.read("EAX")
    edx = ql.arch.regs.read("EDX")
    print(eax,"^",edx, "// DEBUG RESULT OPERATION :", eax^edx)

def vm_or_hook(ql: Qiling) -> None:
    eax = ql.arch.regs.read("EAX")
    edx = ql.arch.regs.read("EDX")
    print(eax,"|",edx, "// DEBUG RESULT OPERATION :", eax|edx)

def vm_and_hook(ql: Qiling) -> None:
    eax = ql.arch.regs.read("EAX")
    edx = ql.arch.regs.read("EDX")
    print(eax,"&",edx, "// DEBUG RESULT OPERATION :", eax&edx)

def vm_equal_hook(ql: Qiling) -> None:
    eax = ql.arch.regs.read("EAX")
    edx = ql.arch.regs.read("EDX")
    print(eax,"==",edx, "// DEBUG RESULT OPERATION :", eax==edx)


def vm_modulo_hook(ql: Qiling) -> None:
    eax = ql.arch.regs.read("EAX")
    modulo_mem = ql.unpack32(ql.mem.read(ql.arch.regs.rbp - 0x8, 4))
    print(eax,"%",modulo_mem, "// DEBUG RESULT OPERATION :", eax%modulo_mem)    

base_addr = ql.loader.images[0].base

# Setup hooks

# ADD
hook_addr_vm_add = base_addr + 0x137e
ql.hook_address(vm_add_hook,hook_addr_vm_add)

# SUB
hook_addr_vm_sub = base_addr + 0x13F2
ql.hook_address(vm_sub_hook,hook_addr_vm_sub) 

# XOR
hook_addr_vm_xor = base_addr + 0x01462
ql.hook_address(vm_xor_hook,hook_addr_vm_xor)

# OR
hook_addr_vm_or = base_addr + 0x14D2
ql.hook_address(vm_or_hook,hook_addr_vm_or)

# AND
hook_addr_vm_and = base_addr + 1542
ql.hook_address(vm_and_hook,hook_addr_vm_and)   

# EQUAL
hook_addr_vm_equal = base_addr + 0x163f
ql.hook_address(vm_equal_hook,hook_addr_vm_equal)

# MODULO
hook_addr_vm_modulo = base_addr + 0x15B8
ql.hook_address(vm_modulo_hook,hook_addr_vm_modulo)

# Emulate
ql.run()
```

On lance l'exécution avec comme entrée utilisateur `ABCDEFGHIJKLMNOPQRSTUVWXYZ012345` pour observer le comportement :

```sh
(qilingenv) root@f15a2555d714:~/InterIUT# python3 emulateVM.py
ABCDEFGHIJKLMNOPQRSTUVWXYZ012345
65 % 56 // DEBUG RESULT OPERATION : 9
9 ^ 49 // DEBUG RESULT OPERATION : 56
0 | 56 // DEBUG RESULT OPERATION : 56
65 % 22 // DEBUG RESULT OPERATION : 21
21 ^ 17 // DEBUG RESULT OPERATION : 4
56 | 4 // DEBUG RESULT OPERATION : 60
66 % 20 // DEBUG RESULT OPERATION : 6
6 ^ 10 // DEBUG RESULT OPERATION : 12
60 | 12 // DEBUG RESULT OPERATION : 60
66 % 24 // DEBUG RESULT OPERATION : 18
18 ^ 14 // DEBUG RESULT OPERATION : 28
60 | 28 // DEBUG RESULT OPERATION : 60
67 % 87 // DEBUG RESULT OPERATION : 67
67 ^ 29 // DEBUG RESULT OPERATION : 94
60 | 94 // DEBUG RESULT OPERATION : 126
67 % 13 // DEBUG RESULT OPERATION : 2
2 ^ 12 // DEBUG RESULT OPERATION : 14
126 | 14 // DEBUG RESULT OPERATION : 126
68 % 95 // DEBUG RESULT OPERATION : 68
68 ^ 6 // DEBUG RESULT OPERATION : 66
126 | 66 // DEBUG RESULT OPERATION : 126
68 % 102 // DEBUG RESULT OPERATION : 68
68 ^ 101 // DEBUG RESULT OPERATION : 33
126 | 33 // DEBUG RESULT OPERATION : 127

[...]

Nop
```

J'ai tronqué l'output car ce dernier est cyclique. En effet, on observe le pattern suivant pour chaque caractère :

- Le caractère subit une première fois un `modulo` avec une valeur, puis le résultat de cette opération subit un `xor` avec une autre valeur. Le résultat impacte une variable valant initialement `0` via un `or`. Cette variable semble être réutilisée pour effectuer chacun des `or` suivants.

- Cette opération sur chaque caractère est effectuée deux fois avec des valeurs pour le `modulo` et `xor` différentes.

Pour rappel, chaque résultat est mis sur la pile. En fin d'exécution, le binaire récupère le dernier élément sur la pile *(qui sera ici le résultat du dernier `or`)* et vérifie si celui-ci vaut `0`, auquel cas le flag est bon. La variable subissant les différents `or` étant affectée deux fois par caractère, il faut donc que chaque résultat après `modulo` puis `xor` soit `0`. Autrement dit, si vous ne voyez toujours pas où je veux en venir, le problème à résoudre est le suivant : 

- Il faut trouver pour chaque caractère sa valeur ASCII tel que les modulos par deux valeurs différentes soient égaux respectivement à deux autres valeurs. 

Autrement dit cela revient à résoudre le problème suivant : 

![](./CodeCogsEqn.svg)


Il s'agit ici d'un théorème bien connu en arithmétique modulaire, le **Théorème des restes chinois**[^4].

[^4]: https://fr.wikipedia.org/wiki/Théorème_des_restes_chinois

Il n'était pas nécessaire de reconnaître ce théorème pour la résolution *(comme vous pouvez le voir dans le script suivant)*. En effet, on peut utiliser le solveur SMT **Z3**[^5] qui n'aura aucun mal à retrouver nos valeurs : 

[^5]: https://github.com/Z3Prover/z3

```py
from z3 import *

# Déclaration des variables pour les 32 caractères du flag
flag_chars = [Int(f"flag_{i}") for i in range(32)]

# Conditions modulo pour chaque caractère du flag
s = Solver()

# Ajout des équations (conditions modulo)
s.add(flag_chars[0] % 56 == 49)
s.add(flag_chars[0] % 22 == 17)
s.add(flag_chars[1] % 20 == 10)
s.add(flag_chars[1] % 24 == 14)
s.add(flag_chars[2] % 87 == 29)
s.add(flag_chars[2] % 13 == 12)
s.add(flag_chars[3] % 95 == 6)
s.add(flag_chars[3] % 102 == 101)
s.add(flag_chars[4] % 75 == 39)
s.add(flag_chars[4] % 81 == 33)
s.add(flag_chars[5] % 36 == 33)
s.add(flag_chars[5] % 21 == 0)
s.add(flag_chars[6] % 52 == 13)
s.add(flag_chars[6] % 123 == 117)
s.add(flag_chars[7] % 23 == 1)
s.add(flag_chars[7] % 119 == 116)
s.add(flag_chars[8] % 65 == 58)
s.add(flag_chars[8] % 21 == 18)
s.add(flag_chars[9] % 105 == 13)
s.add(flag_chars[9] % 24 == 22)
s.add(flag_chars[10] % 31 == 16)
s.add(flag_chars[10] % 112 == 109)
s.add(flag_chars[11] % 5 == 0)
s.add(flag_chars[11] % 41 == 13)
s.add(flag_chars[12] % 55 == 52)
s.add(flag_chars[12] % 85 == 52)
s.add(flag_chars[13] % 109 == 1)
s.add(flag_chars[13] % 77 == 33)
s.add(flag_chars[14] % 112 == 100)
s.add(flag_chars[14] % 40 == 20)
s.add(flag_chars[15] % 70 == 25)
s.add(flag_chars[15] % 101 == 95)
s.add(flag_chars[16] % 87 == 22)
s.add(flag_chars[16] % 50 == 9)
s.add(flag_chars[17] % 94 == 52)
s.add(flag_chars[17] % 30 == 22)
s.add(flag_chars[18] % 98 == 55)
s.add(flag_chars[18] % 61 == 55)
s.add(flag_chars[19] % 36 == 32)
s.add(flag_chars[19] % 10 == 4)
s.add(flag_chars[20] % 66 == 29)
s.add(flag_chars[20] % 92 == 3)
s.add(flag_chars[21] % 114 == 101)
s.add(flag_chars[21] % 95 == 6)
s.add(flag_chars[22] % 7 == 6)
s.add(flag_chars[22] % 25 == 15)
s.add(flag_chars[23] % 77 == 18)
s.add(flag_chars[23] % 63 == 32)
s.add(flag_chars[24] % 63 == 39)
s.add(flag_chars[24] % 49 == 4)
s.add(flag_chars[25] % 86 == 48)
s.add(flag_chars[25] % 8 == 0)
s.add(flag_chars[26] % 115 == 114)
s.add(flag_chars[26] % 120 == 114)
s.add(flag_chars[27] % 62 == 33)
s.add(flag_chars[27] % 58 == 37)
s.add(flag_chars[28] % 22 == 11)
s.add(flag_chars[28] % 61 == 60)
s.add(flag_chars[29] % 75 == 48)
s.add(flag_chars[29] % 74 == 48)
s.add(flag_chars[30] % 60 == 25)
s.add(flag_chars[30] % 92 == 85)
s.add(flag_chars[31] % 124 == 1)
s.add(flag_chars[31] % 56 == 13)

# Contraintes pour les valeurs ASCII (0 à 127)
for i in range(32):
    s.add(And(flag_chars[i] >= 0, flag_chars[i] <= 127))

# Vérification de la faisabilité et résolution
if s.check() == sat:
    m = s.model()
    flag = ""
    for i in range(32):
        solution = m[flag_chars[i]].as_long()
        flag += chr(solution)
    print("Flag =", flag)
else:
    print("Pas de solution")
```

**Flag = interiut{vm_4nd_m47h_eZ_f0r_y0U}**
