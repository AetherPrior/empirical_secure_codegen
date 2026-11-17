import unittest
from adapter import augment, select_knowledge, parse_modules, construct_prompt


class AdapterTests(unittest.TestCase):
    def test_original_rank_major_selection(self):
        self.assertEqual(select_knowledge([['a','b','c'],['b','d','e']]),['a','b','d'])

    def test_task_and_system_preserved(self):
        messages=[{'role':'system','content':'System contract'},
                  {'role':'user','content':'Full task\nsecond line\nrequired signature'}]
        result=augment(messages,['security'],['reference'],'cweval')
        self.assertEqual(result[0],messages[0])
        self.assertEqual(result[1]['content'],construct_prompt(['security'],messages[1]['content'],['reference']))
        self.assertEqual(messages[1]['content'],'Full task\nsecond line\nrequired signature')

    def test_decomposition_validation(self):
        self.assertEqual(parse_modules('[{"description":"Validate input"}]')[0]['description'],'Validate input')
        for value in ['[]','{}','[{"description":""}]']:
            with self.assertRaises(ValueError):parse_modules(value)


if __name__=='__main__':unittest.main()
