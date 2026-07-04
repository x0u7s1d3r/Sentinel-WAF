package detector

import "testing"

func score(fs []Finding) int {
	s := 0
	for _, f := range fs {
		s += f.Severity
	}
	return s
}

func TestSQLSemantic_Attacks(t *testing.T) {
	eng := SQLSemantic{}
	attacks := []string{
		"1' OR '1'='1",
		"admin' OR '1'='1' --",
		"1 UNION SELECT username,password FROM users",
		"1 UNION/**/SELECT 1,2",
		"1 UnIoN sElEcT 1,2",
		"1;DROP TABLE users",
		"1 OR 1=1",
		"1 OR 1=1#",
		"1' OR 1=1 -- -",
		"1' AND SLEEP(5)-- -",
		"admin'--",
		"1' OR 'a'='a",
		"') OR ('1'='1",
	}
	for _, a := range attacks {
		if score(eng.Inspect(a)) == 0 {
			t.Errorf("ATTAQUE NON DÉTECTÉE: %q", a)
		}
	}
}

func TestSQLSemantic_Benign(t *testing.T) {
	eng := SQLSemantic{}
	benign := []string{
		"2",
		"Blue Cotton T-Shirt",
		"please select all items from our shop or store",
		"O'Brien",
		"it's a great deal",
		"1 < 2",
		"salt and pepper",
		"order by name",
		"john.doe@example.com",
		"Rue de la Paix, Lome",
		"SELECT the best option for me",
	}
	for _, b := range benign {
		if s := score(eng.Inspect(b)); s != 0 {
			t.Errorf("FAUX POSITIF sur %q (score=%d)", b, s)
		}
	}
}
