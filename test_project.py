import hashlib
import random
from project import view_pass, add_pass, createpass, encryptor
import json

aeskey = hashlib.sha256("This is the default key".encode()).digest()
test_pass_file = 'tester.json'
enc = encryptor(hashlib.sha256("This is the default key".encode()).digest())
try:
    with open(test_pass_file, 'r') as f:
        passes = json.load(f)
except:
    passes ={}

def test_add_pass():
    add_pass('Test1', 'Pass1', 'platform1',test_pass_file,enc, aeskey=aeskey, passes = passes)
    add_pass('Test2', 'Pass1', 'platform1',test_pass_file,enc, aeskey=aeskey, passes = passes)
    add_pass('Test2', 'Pass2', 'platform2',test_pass_file,enc, aeskey=aeskey, passes = passes)

def test_view_pass():
    assert view_pass(platform='platform1', enc=enc, aeskey=aeskey, passes=passes) == {'Test1' : "Pass1", 'Test2': 'Pass1'}
    assert view_pass(platform='platform2', enc=enc, aeskey=aeskey, passes=passes) == {'Test2' : "Pass2"}
    assert view_pass(platform='This Platform Does Not Exist', enc=enc, aeskey=aeskey, passes=passes) == None

def test_createpass():
    assert type(createpass()) == str
    random.seed(11)
    result = createpass()
    assert result == '5*75$.yx$8'
    random.seed(None)
    assert createpass() != result    
   