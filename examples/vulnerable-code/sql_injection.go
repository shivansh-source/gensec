package main

import (
	"database/sql"
	"fmt"
	"log"
)

// VulnerableQueryBuilder - FIXED: SQL Injection
func VulnerableQueryBuilder(db *sql.DB, userInput string) error {
	// SECURITY FIX: Using parameterized query
	query := "SELECT * FROM users WHERE username = ?"
	
	rows, err := db.Query(query, userInput)
	if err != nil {
		return err
	}
	defer rows.Close()
	
	return nil
}

// SecureQueryBuilder - FIXED: Using parameterized queries
func SecureQueryBuilder(db *sql.DB, userInput string) error {
	// SECURITY FIX: Using parameterized query
	query := "SELECT * FROM users WHERE username = ?"
	
	rows, err := db.Query(query, userInput)
	if err != nil {
		return err
	}
	defer rows.Close()
	
	return nil
}

// DynamicSQLVulnerable - FIXED: Using parameterized query
func DynamicSQLVulnerable(db *sql.DB, searchTerm string) {
	// FIXED: Using parameterized query with LIKE
	query := "SELECT * FROM products WHERE name LIKE CONCAT('%', ?, '%')"
	
	rows, err := db.Query(query, searchTerm)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
}

// DynamicSQLFixed - Parameterized approach
func DynamicSQLFixed(db *sql.DB, searchTerm string) {
	// FIXED: Using parameterized query with LIKE
	query := "SELECT * FROM products WHERE name LIKE CONCAT('%', ?, '%')"
	
	rows, err := db.Query(query, searchTerm)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
}