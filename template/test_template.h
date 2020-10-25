//============================================================================
/**
@file       test_template.cpp
@author     James Hind
@date       03/02/2020
@version    1.0
*/
//============================================================================

#include <iostream>
#include <assert.h>
#include <string>
#include <functional>

//============================================================================
/** @brief  A structure for holding assertion failures for use in the `ASSERT` macro.
  */
struct assert_fail
{
    const std::string description;
    int line_number;
};

//============================================================================
/** @brief  A structure for holding test cases to facilitate test iteration.
  */
struct test_case 
{
    const std::string name;
    std::function<void ()> execute;
};

//============================================================================
/** @brief  Custom ASSERT macro to allow continuation of testing on a failure.
  */
#define ASSERT( test ) \
    void( test ? 0 : throw assert_fail( { "ASSERT( " #test " )", __LINE__ } ) )

//============================================================================
/// Array for test case registration
test_case tests[] = {

    "Test Case 1",
    []()
    {
        ASSERT( 1 == 1 );
    },

    "Test Case 2",
    []()
    {
    }

};

//============================================================================
int main( /*int argc, char* argv[]*/ )
{
    bool flag_fail = false;

    for( auto test : tests )
    {
        try
        {
            std::cout << "Testing: " << test.name << std::endl;
            test.execute();
        }
        catch( assert_fail& e )
        {
            flag_fail = true;
            std::cout << "\nTest Failed:\n\t"
                << e.description << " at line " << e.line_number << "\n" << std::endl;
        }
    }

    if( flag_fail )
    {
        std::cout << "\nFAILURE! Some tests did not pass\n" << std::endl;
        return 1;
    }
    std::cout << "\nSUCCESS! All tests passed\n" << std::endl;
    return 0;
}


