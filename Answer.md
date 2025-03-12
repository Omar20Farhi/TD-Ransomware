Question 1
L'algorithme employé est le chiffrement XOR. Il est considéré comme peu sécurisé, car si un attaquant dispose à la fois d'une version chiffrée et non chiffrée d'un même fichier, il peut en déduire la clé utilisée pour le cryptage.

Question 2
Il n'est pas pertinent de hacher directement le sel et la clé, car cela n'améliore pas réellement la sécurité. Ces éléments sont déjà aléatoires et uniques, et les hacher ne les rendrait pas plus difficiles à deviner. En revanche, un HMAC est principalement utilisé pour assurer l'intégrité et l'authenticité d'un message, ce qui ne correspond pas à l'objectif principal du chiffrement de fichiers dans ce cas.

Question 3
La vérification de l'existence d'un fichier token.bin permet d'éviter l'écrasement des données de chiffrement existantes. En effet, la suppression ou la modification de ce fichier pourrait empêcher le déchiffrement des fichiers précédemment chiffrés, entraînant ainsi une perte irrémédiable d'informations.

Question 4
Pour s'assurer que la clé fournie est correcte, il suffit de comparer le token dérivé à partir du sel et de la clé candidate avec le token d'origine stocké. Si les deux correspondent, la clé est valide.








