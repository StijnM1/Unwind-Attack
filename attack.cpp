#include "sbt_opt.hpp"
#include "program_options.hpp"
#include <iostream>
#include <vector>  
#include <fstream>
#include <string>
#include <unordered_set>
namespace po = program_options;

state_t original_input; // input lfsr_register value
state_t original_output; // output crypto_buffer

state_t original_key; // for testing purposes the actual true key

state_t key_known_bits_mask; // mask to limit the key search space

/* 
    Class representating a List
    BPmask is a mask representing the chosen byte paths
    keymask is a mask representing the keybits needed (BPmask implies keymask)
    keylist is a list of all valid keys where relevant bits are specified according to keymask 
*/

class List{
    public:
        state_t BPmask;
        state_t keymask;
        std::vector<state_t> keylist;
};

struct state_hash {
     size_t operator()(state_t x) const { return _h(x.u64); }
     std::hash<uint64_t> _h;
};

void printvec(const std::vector<state_t> vec){
    for (state_t i: vec)
        {std::cout << i << ' ';}
    std::cout << std::endl;
    };

void printset(const std::unordered_set<state_t, state_hash> set){
    for (state_t i: set)
        {std::cout << i << ' ';}
    std::cout << std::endl;
    };

bool check_key_mask(const state_t key, const state_t keymask){
    if (((key.u64 ^ original_key.u64) & (key_known_bits_mask.u64 & keymask.u64)) == 0)
        {return true;}
    return false;
    }

void apply_key_mask(List& list){
    for(int i=0; i<list.keylist.size();)
    {
        if (check_key_mask(list.keylist[i], list.keymask))
        {           
            i++;continue;
        }
        std::swap(list.keylist[i], list.keylist.back());
        list.keylist.pop_back();
    }
}

bool valid_mitm(const state_t key, state_t BPmask){
    state_t original_BPmask = BPmask;
    std::vector<state_t> IList; // list of all possible inputs (per operation)
    std::vector<state_t> OList; // list of all possible outputs (per operation)
    std::unordered_set<state_t,state_hash> OHash;

    // create backwards list first
    state_t initial_output_state = original_output;
    OList.push_back(initial_output_state);

    for (int round = 7; round > 3; --round) {
        state_t control = SBTopt::control_Nr_Gr(round, key, original_input);

        // inverse S boxes
        IList.swap(OList);
        OList.clear();
        for (state_t input : IList){
            SBTopt::sbox_inv(input);
            OList.push_back(input.u64&BPmask.u64);
        }

        // inveres nibble switch
        IList.swap(OList);
        OList.clear();
        for (state_t input : IList){
            SBTopt::nibbleswitch_inv(input, control);
            OList.push_back(input.u64&BPmask.u64);
        }

        SBTopt::bytepermutation_inv(BPmask);

        // inverse byte permutation
        IList.swap(OList);
        OList.clear();
        for (state_t input : IList){
            SBTopt::bytepermutation_inv(input);
            OList.push_back(input.u64&BPmask.u64);
        }

        

        for (int n = 15; n >= 0; --n)       
        {
            int pos = n^1;
            if (BPmask.getnibble(pos) == 0) continue; 
            
            IList.swap(OList);
            OList.clear();
            for (const state_t& input : IList){
                state_t val = input;
                // uses function: bool extcrumbused = partial_grid_permutation(output, pos, BP_mask, extcrumb, control)
                // which modifies output (in place) and returns true if it needed the crumb value and that was outside the BP_mask
                bool extcrumbused = SBTopt::partial_grid_permutation_inv(val, n, BPmask, 0, control);
                OList.push_back(val.u64 & BPmask.u64);
                if (extcrumbused==0) continue;
                val = input;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 1, control);
                OList.push_back(val.u64 & BPmask.u64);
                val = input;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 2, control);
                OList.push_back(val.u64 & BPmask.u64);
                val = input;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 3, control);
                OList.push_back(val.u64 & BPmask.u64);
                }
        }
    }

    std::unordered_set<state_t,state_hash> backwards_list(std::make_move_iterator(OList.begin()),std::make_move_iterator(OList.end()));

    // create forwards list
    IList.clear();
    OList.clear();
    state_t initial_state = original_input;
    SBTopt::bitpermutation(initial_state);
    OList.push_back(initial_state);

    BPmask = original_BPmask;

    for (int round = 0; round < 4 ; ++round){
        
        state_t control = SBTopt::control_Nr_Gr(round, key, original_input);
        // grid permutation
        for (int n = 0; n < 16; ++n)       
        {
            int pos = n^1;
            if (BPmask.getnibble(pos) == 0) continue; 
            
            IList.swap(OList);
            OList.clear();
            for (const state_t& input : IList){
                state_t val = input;
                // uses function: bool extcrumbused = partial_grid_permutation(output, pos, BP_mask, extcrumb, control)
                // which modifies output (in place) and returns true if it needed the crumb value and that was outside the BP_mask
                bool extcrumbused = SBTopt::partial_grid_permutation(val, n, BPmask, 0, control);
                OList.push_back(val.u64 & BPmask.u64);
                if (extcrumbused==0) continue;
                val = input;
                SBTopt::partial_grid_permutation(val, n, BPmask, 1, control);
                OList.push_back(val.u64 & BPmask.u64);
                val = input;
                SBTopt::partial_grid_permutation(val, n, BPmask, 2, control);
                OList.push_back(val.u64 & BPmask.u64);
                val = input;
                SBTopt::partial_grid_permutation(val, n, BPmask, 3, control);
                OList.push_back(val.u64 & BPmask.u64);
                }
        }
        
        if (round == 2 || round == 4 || round == 6)
        {
            // filter unique values every odd round
            OHash.clear();
            OHash.reserve(OList.size());
            for (state_t val : OList)
                OHash.emplace(val);
            OList.clear();
            for (state_t val : OHash)
                OList.emplace_back(val);
        }
        
        
        //Byte permutation
        SBTopt::bytepermutation(BPmask);
        
        IList.swap(OList);
        OList.clear();
        for (state_t input : IList){
            SBTopt::bytepermutation(input);
            OList.push_back(input.u64&BPmask.u64);
        }
        
        //Nibble switch
        IList.swap(OList);
        OList.clear();
        for (state_t input : IList){
            SBTopt::nibbleswitch(input, control);
            OList.push_back(input.u64&BPmask.u64);
        }
        
        //S boxes
        IList.swap(OList);
        OList.clear();
        for (state_t input : IList){
            SBTopt::sbox(input);
            OList.push_back(input.u64&BPmask.u64);
        }
        
    }
    
    for (state_t output : OList){
        if (backwards_list.count(output)>0){
            return true;
        }
    }

    return false;
}

List create_single_list(const int& byte_path_number){
    List list;
    
    //create byte path mask
    list.BPmask.u64 = 0;
    list.BPmask.setbyte(byte_path_number, 255);

    //create keymask
    list.keymask = SBTopt::determine_keymask(list.BPmask);

    //create keylist
    uint64_t z = 0;
    
    do{
            --z;
            z &= list.keymask.u64;

            if (!check_key_mask(z, list.keymask))
            {continue;}
            
            if (valid_mitm(z, list.BPmask)){
                list.keylist.push_back(z);
            };
            
    }
    while (z != 0);
    
    return list;
}

List combine_lists(const List& list_a, const List& list_b){

    List list_c;
    uint64_t z = 0;

    list_c.BPmask = list_a.BPmask.u64|list_b.BPmask.u64;
    list_c.keymask = list_a.keymask.u64|list_b.keymask.u64;

    for (const state_t& partial_key : list_a.keylist) {
        
        do{
            --z;
            z &= list_b.keymask.u64&(~list_a.keymask.u64);
            state_t ext_key = z^partial_key.u64;

            if (!check_key_mask(ext_key, list_c.keymask)){
                continue;
            }

            if (valid_mitm(ext_key, list_c.BPmask)){
                list_c.keylist.push_back(ext_key);
        };
        }while (z != 0); // extend partial_key to all possible extended keys
    };

    return list_c;
};

template<typename T>
void write_vector(const std::string& filename, const std::vector<T>& vec)
{
     std::ofstream f(filename.c_str(), std::ios::binary);
     if (!f) { /* file open error */ ; return ; }
     f.write(reinterpret_cast<const char*>(& vec[0]),
sizeof(T)*vec.size() );
}

template<typename T>
void read_vector(const std::string& filename, std::vector<T>& vec)
{
     std::ifstream f(filename.c_str(), std::ios::binary);
     if (!f) { /* file open error */ ; return ; }
     // get total file length
     f.seekg(0, std::ios_base::end);
     size_t len = f.tellg();
     f.seekg(0, std::ios_base::beg);
     if ((len % sizeof(T)) != 0) { /* output file length is not proper
multiple error */; return ; }
     // resize vector to correct size
     vec.resize(len / sizeof(T));
     // load file into vector
     f.read(reinterpret_cast<char*>(& vec[0]), len );

}

int main(int argc, char** argv){

	po::options_description opts("Command line options");
	opts.add_options()
		("help,h", "Show options") // short option & long option
		("input,i", po::value<std::uint64_t>(&original_input.u64), "Provide input block")
		("key,k", po::value<std::uint64_t>(&original_key.u64), "Provide key (to compute output block)")
		("knownkeybitmask", po::value<std::uint64_t>(&key_known_bits_mask.u64)->default_value(0), "Leak key bits to attack")
		("output,o", po::value<std::uint64_t>(&original_output.u64), "Provide output block")
		;
	po::variables_map vm;
	// parse command line
	po::store(po::parse_command_line(argc, argv, opts, false, false), vm);
	// set default values if option was not given, and store arguments in variables
	po::notify(vm);

	if (vm.count("help") || vm.count("input")==0 || vm.count("key")+vm.count("output")==0)
	{
		po::print_options_description({opts}); // add other opts as desired in list
		return 0;
	}
	if (vm.count("output")==0)
	{
	    original_output = SBTopt::SBT_cipher(original_key, original_input);
	}
	std::cout << "Input  :" << original_input << std::endl;
	std::cout << "Output :" << original_output << std::endl;
	std::cout << "Key    :" << original_key << std::endl;
	std::cout << "KeyLeak:" << key_known_bits_mask << std::endl;

    List L1 = create_single_list(7-0);
    List L2 = create_single_list(7-1);
    List L3 = create_single_list(7-2);
    List L4 = create_single_list(7-3);
    List L5 = create_single_list(7-4);
    List L6 = create_single_list(7-5);
    List L7 = create_single_list(7-6);
    List L8 = create_single_list(7-7);

    std::cout << "L1 size: " << L1.keylist.size() << std::endl;
    std::cout << "L2 size: " << L2.keylist.size() << std::endl;
    std::cout << "L3 size: " << L3.keylist.size() << std::endl;
    std::cout << "L4 size: " << L4.keylist.size() << std::endl;
    std::cout << "L5 size: " << L5.keylist.size() << std::endl;
    std::cout << "L6 size: " << L6.keylist.size() << std::endl;
    std::cout << "L7 size: " << L7.keylist.size() << std::endl;
    std::cout << "L8 size: " << L8.keylist.size() << std::endl;

    List L67 = combine_lists(L6, L7);
    std::cout << "L67 size: " << L67.keylist.size() << std::endl;

    List L167 = combine_lists(L67, L1);
    std::cout << "L167 size: " << L167.keylist.size() << std::endl;

    List L1567 = combine_lists(L167, L5);
    std::cout << "L1567 size: " << L1567.keylist.size() << std::endl;

    List L15678 = combine_lists(L1567, L8);
    std::cout << "L15678 size: " << L15678.keylist.size() << std::endl;

    List L125678 = combine_lists(L15678, L2);
    std::cout << "L125678 size: " << L125678.keylist.size() << std::endl;

    List L1235678 = combine_lists(L125678, L3);
    std::cout << "L1235678 size: " << L1235678.keylist.size() << std::endl;

    List L12345678 = combine_lists(L1235678, L4);
    std::cout << "L12345678 size: " << L12345678.keylist.size() << std::endl;

    std::cout << "Computed key: ";
    printvec(L12345678.keylist);
    std::cout << "Original key: " << original_key << std::endl;

    return 0;
};