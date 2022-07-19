Jusqu'où avez-vous été ? (quelle semaine ?)
- Jusqu'à la semaine 13 (et on a rajouté quelques extensions simples)

Qu'est-ce que vous avez fait/pas fait ? 

- La totalité du projet à été traitée (c-à-d faite).

**Commentaire général sur le projet :** 
Le projet s'est bien déroulé, nous l'avons trouvé tout à fait guidé et à la porté d'un étudiant de BA4. 
Le projet était tout aussi intéressant qu'éducatif mais si nous devions cité un seul bémol : 	
- La répétition et la redondance entre les 3 dernières semaines (implémenter STATS, GET et SET plusieurs fois d'affilés)

Un autre commentaire concernant le code que nous avons écrit 
- Le code qui concernent les dernières semaines (`ckvs_httpd.c`, `ckvs_client.c`, `ckvs_rpc.c`)
manque clairement de rigueur (modularisation, constantes ...) et nous nous en excusons, cela est due aux dernières semaines du semestre qui ont été chargées et qui nous ont empechés de produire du bon code.


**Extension :** 
Nous avons décider d'ajouter quelques extensions (simplistes car elles ne sont disponible qu'en local) qui rendent plus logique le projet 	
- La commande 'create' :  	
```c
./cryptkvs <filename> create 
```
qui permet de créer une nouvelle base de données CKVS.
- La commande 'delete' :
```c
./cryptkvs <filename> delete <key> <password>
```
qui permet de supprimer une entrée de la base de données.

 
