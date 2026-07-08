// db.go — vraie base SQLite (pur Go, sans CGO) pour l'Attack Lab.
//
// La base est créée en mémoire au démarrage et pré-remplie avec un jeu de
// données réaliste (comptes, produits, messages, commandes). Les fonctions de
// requête sont VOLONTAIREMENT vulnérables : elles concatènent directement les
// entrées de l'utilisateur dans le SQL, sans requête préparée. Une injection
// réussie extrait donc de VRAIES données de la base.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "modernc.org/sqlite"
)

var db *sql.DB

// initDB ouvre la base SQLite en mémoire, crée le schéma et insère les données.
func initDB() {
	var err error
	// "file::memory:?cache=shared" garde la base vivante tant que la connexion
	// existe ; on limite le pool à 1 pour partager la même base en mémoire.
	db, err = sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		log.Fatalf("ouverture base : %v", err)
	}
	db.SetMaxOpenConns(1)

	schema := `
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT,
  password TEXT,
  email TEXT,
  role TEXT,
  credit_card TEXT
);
CREATE TABLE products (
  id INTEGER PRIMARY KEY,
  name TEXT,
  category TEXT,
  price REAL,
  stock INTEGER
);
CREATE TABLE messages (
  id INTEGER PRIMARY KEY,
  sender TEXT,
  recipient TEXT,
  body TEXT,
  private INTEGER
);
CREATE TABLE orders (
  id INTEGER PRIMARY KEY,
  username TEXT,
  product TEXT,
  amount REAL,
  status TEXT
);`
	if _, err := db.Exec(schema); err != nil {
		log.Fatalf("création schéma : %v", err)
	}

	seed := `
INSERT INTO users (username,password,email,role,credit_card) VALUES
 ('admin','5f4dcc3b5aa765d61d8327deb882cf99','admin@shop.local','administrator','4539-1488-0343-6467'),
 ('alice','202cb962ac59075b964b07152d234b70','alice@shop.local','customer','5105-1051-0510-5100'),
 ('bob','e10adc3949ba59abbe56e057f20f883e','bob@shop.local','customer','4916-6734-7572-5015'),
 ('charlie','25f9e794323b453885f5181f1b624d0b','charlie@corp.local','manager','3782-8224-6310-005'),
 ('dave','d8578edf8458ce06fbc5bb76a58c5ca4','dave@shop.local','customer','6011-1111-1111-1117'),
 ('root','63a9f0ea7bb98050796b649e85481845','root@shop.local','superuser','4485-2758-1234-5678');

INSERT INTO products (name,category,price,stock) VALUES
 ('Clavier mécanique','périphériques',89.90,42),
 ('Souris gamer','périphériques',49.50,17),
 ('Écran 27 pouces','écrans',329.00,8),
 ('Casque audio','audio',129.90,25),
 ('Webcam HD','périphériques',69.00,0),
 ('Disque SSD 1To','stockage',109.00,54),
 ('Routeur Wi-Fi 6','réseau',159.90,12);

INSERT INTO messages (sender,recipient,body,private) VALUES
 ('admin','alice','Bienvenue sur la boutique !',0),
 ('alice','admin','Ma commande est-elle expédiée ?',0),
 ('root','admin','Mot de passe serveur : Pr0d!2026_srv',1),
 ('charlie','bob','Le budget confidentiel est de 250000 EUR',1),
 ('admin','root','Clé API paiement : sk_live_9f8a7b6c5d4e3f2a1b',1);

INSERT INTO orders (username,product,amount,status) VALUES
 ('alice','Clavier mécanique',89.90,'expédiée'),
 ('bob','Écran 27 pouces',329.00,'en préparation'),
 ('charlie','Disque SSD 1To',109.00,'livrée'),
 ('dave','Casque audio',129.90,'annulée');`
	if _, err := db.Exec(seed); err != nil {
		log.Fatalf("insertion données : %v", err)
	}
	log.Printf("base SQLite initialisée (6 comptes, 7 produits, 5 messages, 4 commandes)")
}

// --- Requêtes VOLONTAIREMENT vulnérables (concaténation directe) ---

// rows exécute une requête et renvoie les lignes formatées en texte + le SQL.
func vulnerableQuery(query string) (sqlText, result string, vulnerable bool, err error) {
	rows, err := db.Query(query)
	if err != nil {
		return query, "", false, err
	}
	defer rows.Close()

	cols, _ := rows.Columns()
	var out strings.Builder
	out.WriteString(strings.Join(cols, " | ") + "\n")
	out.WriteString(strings.Repeat("-", 40) + "\n")

	n := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return query, "", false, err
		}
		cells := make([]string, len(cols))
		for i, v := range vals {
			cells[i] = fmt.Sprintf("%v", v)
		}
		out.WriteString(strings.Join(cells, " | ") + "\n")
		n++
	}
	return query, out.String(), n > 0, nil
}

// searchProducts : recherche vulnérable dans les produits (SQLi).
func searchProducts(id string) (string, string, bool, error) {
	// VULNÉRABLE : concaténation directe de l'entrée dans le SQL.
	q := "SELECT id, name, category, price FROM products WHERE id = '" + id + "'"
	return vulnerableQuery(q)
}

// loginNoSQLStyle : authentification vulnérable (utilisée pour la démo NoSQL/SQLi login).
func loginVulnerable(user, pass string) (string, string, bool, error) {
	q := "SELECT id, username, role FROM users WHERE username = '" + user + "' AND password = '" + pass + "'"
	return vulnerableQuery(q)
}
