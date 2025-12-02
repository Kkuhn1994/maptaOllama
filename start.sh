source venv/bin/activate
pip3 install --upgrade google-generativeai
export OPENAI_API_KEY="dein_test_api_key_hier"
export GOOGLE_API_KEY="dein-key-hier"
echo "dependencies installed"
python3 main.py
