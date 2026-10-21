# extension-pipeline

Code for my master's thesis *LLM-Guided Automatic Verification of Message-Passing
Vulnerabilities* (Kerem Ergür, LMU Munich, 2026).

The pipeline takes static-analysis findings for Chrome extensions (CodeQL, CoCo or
DoubleX reports). An LLM classifies each finding and writes an exploit payload, and the
verifier then loads the extension in Chrome to check whether the payload fires. The
thesis describes the method and the results.

## Layout

    src/analyze_extensions.py   analyzer entry point (code in src/analyzer/)
    src/verify_extensions.py    verifier entry point (code in src/verifier/)
    src/mock_server/            local server the verifier uses to observe network requests
    src/config.py               all settings and their defaults
    env/.env.fullrun            settings of the thesis full run
    run_parallelx.sh            runs the verifier sharded over many Docker containers

## Running

The analyzer and the verifier each have their own image. Mount the directory that holds
your data at `/data` and point the paths in the env file at it.

    docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) \
        -f Dockerfile.analyzer -t analyze-extensions .
    docker run -it --rm -v /path/to/data:/data -u $(id -u):$(id -g) \
        --env-file=env/.env.fullrun analyze-extensions

    docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) \
        -f Dockerfile.verifier -t verify-ext-$USER .
    docker run -it --rm -v /path/to/data:/data -u $(id -u):$(id -g) \
        --env-file=env/.env.fullrun --shm-size=2g \
        -e RESULTS_TO_VERIFY=latest verify-ext-$USER

`RESULTS_TO_VERIFY` names the analyzer run to verify (a folder in `RESULTS_ANALYSIS_DIR`),
or `latest` for the newest one.

Any setting in `src/config.py` can be overridden by an environment variable of the same
name. In `env/.env.fullrun` the paths, the Chrome binary and the LLM server are left for
you to fill in. The thesis runs used a vLLM server and Chrome for Testing 126.

For large verification runs, `run_parallelx.sh` splits the analyzer output into shards
and runs each shard in its own container. A full run with two retry passes over the
extensions that failed:

    ./run_parallelx.sh all --src DIR_WITH_ANALYZER_RESULTS --out fullrun -n 2 --shards 100
    ./run_parallelx.sh status --run fullrun

Runs are written to `~/verifier/<name>`. Use `--dataset` (folder of `<extension id>.crx`
files) and `--chrome` (Chrome path inside the container, where your home is mounted at
`/work`) for your setup. The header of the script lists all options.

`Dockerfile` builds a single image that runs either stage, chosen by passing `analyzer`
or `verifier` as the command.

## Versions

| Tag | |
|---|---|
| `thesis-public` | the thesis code as published |
| `thesis-analyzer-submission` | analyzer at thesis submission, as used for the experiments |
| `thesis-verifier-tok-1`, `thesis-verifier-tok-2` | the two verifier versions used for the experiments |
| `thesis-start` | the pipeline this work started from |

`thesis-verifier-tok-2` also has the verifier's benchmark and result notes, which are not
on main.

## Credits

The original pipeline this project builds on was written by Zacharias Beermann.
Çağdaş Varol Tok maintained and improved the browser verifier.
