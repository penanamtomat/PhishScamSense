"""
Apache Airflow DAG for automated model retraining pipeline.
Scheduled to run periodically to ingest new threat data and retrain the model.
"""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator

default_args = {
    "owner": "phishsense",
    "depends_on_past": False,
    "email_on_failure": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}


def ingest_threat_data(**kwargs):
    """Ingest latest threat intelligence data."""
    from ml.src.data.data_loader import prepare_training_data

    urls, labels = prepare_training_data(include_openphish=True)
    kwargs["ti"].xcom_push(key="dataset_size", value=len(urls))
    return {"urls_count": len(urls)}


def retrain_model(**kwargs):
    """Retrain the PhishSense model with updated data."""
    from ml.src.training.train import train_pipeline

    from ml.src.data.data_loader import prepare_training_data

    urls, labels = prepare_training_data(include_openphish=True)
    train_pipeline(urls, labels, experiment_name="phishsense_retrain")


def update_bloom_filter(**kwargs):
    """Update the Bloom Filter with latest threat URLs."""
    # TODO: Regenerate Bloom filter and push to API
    pass


with DAG(
    "phishsense_retrain",
    default_args=default_args,
    description="PhishSense model retraining pipeline",
    schedule_interval=timedelta(days=7),
    start_date=datetime(2026, 1, 1),
    catchup=False,
    tags=["phishsense", "ml"],
) as dag:
    ingest_task = PythonOperator(
        task_id="ingest_threat_data",
        python_callable=ingest_threat_data,
    )

    retrain_task = PythonOperator(
        task_id="retrain_model",
        python_callable=retrain_model,
    )

    bloom_filter_task = PythonOperator(
        task_id="update_bloom_filter",
        python_callable=update_bloom_filter,
    )

    ingest_task >> retrain_task >> bloom_filter_task
