from evaluation.interface import EvaluationConfig
from evaluation.evaluator import Evaluator
from vara.analyzer import analyze


def main():
    config = EvaluationConfig(
        dataset_path="evaluation/benchmark/Dataset.json",
        repos_dir="data/repos",
        output_dir="evaluation/reports",
        max_cves=0,  # 0 = no limit
        num_workers=10,  # parallel workers, 1 = sequential
    )
    evaluator = Evaluator(config, tool=analyze)

    # Option 1: Run all 3 steps (creates new timestamped folder)
    evaluator.run_all()

    # Option 2: Run steps independently
    # run_dir = evaluator.run()                                              # Step 1: run tool
    # comparison_path = evaluator.compare("evaluation/reports/20260328_171000/results.json")  # Step 2: compare
    # evaluator.metrics("evaluation/reports/20260328_171000/comparison.json")                 # Step 3: metrics


if __name__ == "__main__":
    main()
