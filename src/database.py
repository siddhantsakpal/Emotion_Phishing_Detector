#database.py
import os
import mysql.connector
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(dotenv_path)

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "emotion_phishing_dbs")
    
    )
def log_analysis(result):
    """Saves the AI's results into MySQL."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = """INSERT INTO analysis_logs
                 (email_content, detected_keywords, fear_score, urgency_score,
                  ml_phishing_prob, final_decision)
                 VALUES (%s, %s, %s, %s, %s, %s)"""

        fear    = result["emotions"].get("fear", 0.0)
        urgency = result["emotions"].get("surprise", 0.0)

        values = (
            result["email_content"],
            ", ".join(result["keywords"]),
            float(fear),
            float(urgency),
            float(result["ml_probs_combined"]["phishing"]),
            result["decision"]
        )

        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        print("Successfully logged to MySQL!")
    except Exception as e:
        print(f"MySQL Error: {e}")


def get_all_analysis(selected_date=None):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    base_query = """
        SELECT id,
               email_content,
               ml_phishing_prob,
               final_decision,
               fear_score,
               urgency_score,
               detected_keywords,
               timestamp
        FROM analysis_logs
    """

    if selected_date:
        base_query += " WHERE DATE(timestamp) = %s ORDER BY timestamp DESC"
        cursor.execute(base_query, (selected_date,))
    else:
        base_query += " ORDER BY timestamp DESC"
        cursor.execute(base_query)

    records = cursor.fetchall()

    count_query = """
        SELECT final_decision, COUNT(*) as count
        FROM analysis_logs
    """

    if selected_date:
        count_query += " WHERE DATE(timestamp) = %s GROUP BY final_decision"
        cursor.execute(count_query, (selected_date,))
    else:
        count_query += " GROUP BY final_decision"
        cursor.execute(count_query)

    counts = cursor.fetchall()

    phishing_count = next(
        (row["count"] for row in counts
         if row["final_decision"].lower() == "phishing"), 0
    )

    # FIX: Engine outputs "Legitimate" not "safe" — match correctly
    legit_count = next(
        (row["count"] for row in counts
         if row["final_decision"].lower() == "legitimate"), 0
    )

    suspicious_count = next(
        (row["count"] for row in counts
         if row["final_decision"].lower() == "suspicious"), 0
    )

    cursor.close()
    conn.close()

    return records, phishing_count, legit_count, suspicious_count
