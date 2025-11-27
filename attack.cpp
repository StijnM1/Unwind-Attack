#include "sbt_opt.hpp"
#include "program_options.hpp"
#include <iostream>
#include <vector>  
#include <fstream>
#include <string>
#include <unordered_set>
#include <iomanip>
#include <random>
#include <thread>

namespace po = program_options;

state_t original_input; // input lfsr_register value
state_t original_output; // output crypto_buffer

state_t original_key; // for testing purposes the actual true key

state_t key_known_bits_mask; // mask to limit the key search space

std::ofstream myfile("output.txt");

std::map<int, double> weights;

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

double check_probs(std::map<state_t, double> probs) {
    double total = 0;
    for (const auto& val : probs) {
        total += val.second;
    }
    return total;
}

bool mapeqlist(std::map<state_t, double> probs, std::vector<state_t> vec) {
    std::set<state_t> s(vec.begin(), vec.end());
    vec.assign(s.begin(), s.end());
    
    if (probs.size() != s.size()) { return false; }
    for (state_t p : s) {
        if (probs.contains(p)) { continue; }
        else { return false; }
    }
    return true;
}

void printmap(const std::map<state_t, double> map) {
    std::cout << "-----PRINTING MAP-----" << std::endl;
    std::cout << "Map probability: " << check_probs(map) << std::endl;
    for (auto p : map)
    {
        if (p.second < 0) { continue; }
        std::cout << p.first << p.second << ' ' << std::endl;
    }
    std::cout << "------END OF MAP------" << std::endl;
};

std::map<state_t, double> change_keymap(std::map<state_t, double> probs, state_t old_keymap, state_t new_keymap) {
    if (probs.count(new_keymap) == 0){
        probs.insert({ new_keymap, probs[old_keymap]});
        probs.erase(old_keymap);
    }
    else if (new_keymap != old_keymap){
        probs[new_keymap] += probs[old_keymap];
        probs.erase(old_keymap);
    }

    /*for (auto it = probs.begin(); it != probs.end(); )
        if (it->second == 0)
            it = probs.erase(it);
        else
            ++it;*/
    return probs;
};

bool contains(const std::vector<state_t>& vec, state_t state) {
    for (int i = 0; i < vec.size(); ++i) {
        if (vec[i] == state) {
            return true;
        }
    }
    return false;
}

int hammingweight(int64_t vec)
{
    int weight = 0;
    int64_t N = vec;
    while (N)
    {
        weight++;
        N &= N - 1;
    }
    return weight;
}

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

bool valid_mitm_probs(const state_t key, state_t BPmask) {
    state_t original_BPmask = BPmask;

    // create backwards list first
    state_t initial_output_state = original_output;

    std::map<state_t, double> probs_fw_in;
    std::map<state_t, double> probs_fw_out;
    std::map<state_t, double> probs_bw_in;
    std::map<state_t, double> probs_bw_out;

    probs_bw_out[initial_output_state] = 1;

    for (int round = 7; round > 3; --round) {
        state_t control = SBTopt::control_Nr_Gr(round, key, original_input);

        probs_bw_in.swap(probs_bw_out);
        probs_bw_out.clear();

        //probs 
        for (auto p : probs_bw_in) {
            state_t input = p.first;
            SBTopt::sbox_inv(input);
            probs_bw_out[input.u64 & BPmask.u64] += p.second;
        }

        probs_bw_in.swap(probs_bw_out);
        probs_bw_out.clear();

        //nibble switch
        for (auto p : probs_bw_in) {
            state_t input = p.first;
            SBTopt::nibbleswitch_inv(input, control);
            probs_bw_out[input.u64 & BPmask.u64] += p.second;
        }

        //byte permutation
        SBTopt::bytepermutation_inv(BPmask);

        probs_bw_in.swap(probs_bw_out);
        probs_bw_out.clear();

        for (auto p : probs_bw_in) {
            state_t input = p.first;
            SBTopt::bytepermutation_inv(input);
            probs_bw_out[input.u64 & BPmask.u64] += p.second;
        }

        //grid permutation
        for (int n = 15; n >= 0; --n)
        {
            int pos = n ^ 1;
            if (BPmask.getnibble(pos) == 0) continue;

            probs_bw_in.swap(probs_bw_out);
            probs_bw_out.clear();

            for (auto input : probs_bw_in) {
                state_t val = input.first;
                auto input_prob = input.second;

                // uses function: bool extcrumbused = partial_grid_permutation(output, pos, BP_mask, extcrumb, control)
                // which modifies output (in place) and returns true if it needed the crumb value and that was outside the BP_mask
                bool extcrumbused = SBTopt::partial_grid_permutation_inv(val, n, BPmask, 0, control);
                state_t output = val.u64 & BPmask.u64;

                if (extcrumbused == 0) {
                    probs_bw_out[output] += input_prob;
                    continue;
                }

                probs_bw_out[output] += input_prob / 4.;

                val = input.first;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 1, control);
                probs_bw_out[val.u64 & BPmask.u64] += input_prob / 4.;

                val = input.first;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 2, control);
                probs_bw_out[val.u64 & BPmask.u64] += input_prob / 4.;

                val = input.first;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 3, control);
                probs_bw_out[val.u64 & BPmask.u64] += input_prob / 4.;
            }
        }
    }

    state_t initial_state = original_input;
    SBTopt::bitpermutation(initial_state);
    probs_fw_out[initial_state] = 1;

    BPmask = original_BPmask;

    for (int round = 0; round < 4; ++round) {
        state_t control = SBTopt::control_Nr_Gr(round, key, original_input);

        // grid permutation
        for (int n = 0; n <= 15; ++n)
        {
            int pos = n ^ 1;
            if (BPmask.getnibble(pos) == 0) continue;

            probs_fw_in.swap(probs_fw_out);
            probs_fw_out.clear();

            for (auto input : probs_fw_in) {
                state_t val = input.first;
                auto input_prob = input.second;

                // uses function: bool extcrumbused = partial_grid_permutation(output, pos, BP_mask, extcrumb, control)
                // which modifies output (in place) and returns true if it needed the crumb value and that was outside the BP_mask
                bool extcrumbused = SBTopt::partial_grid_permutation_inv(val, n, BPmask, 0, control);
                state_t output = val.u64 & BPmask.u64;

                if (extcrumbused == 0) {
                    probs_fw_out[output] += input_prob;
                    continue;
                }

                probs_fw_out[output] += input_prob / 4.;

                val = input.first;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 1, control);
                probs_fw_out[val.u64 & BPmask.u64] += input_prob / 4.;

                val = input.first;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 2, control);
                probs_fw_out[val.u64 & BPmask.u64] += input_prob / 4.;

                val = input.first;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 3, control);
                probs_fw_out[val.u64 & BPmask.u64] += input_prob / 4.;
            }
        }

        //Byte permutation
        SBTopt::bytepermutation(BPmask);

        probs_fw_in.swap(probs_fw_out);
        probs_fw_out.clear();

        for (auto p : probs_fw_in) {
            state_t input = p.first;
            SBTopt::bytepermutation(input);
            probs_fw_out[input.u64 & BPmask.u64] += p.second;
        }

        //Nibble switch
        probs_fw_in.swap(probs_fw_out);
        probs_fw_out.clear();

        for (auto p: probs_fw_in) {
            state_t input = p.first;
            SBTopt::nibbleswitch(input, control);
            probs_fw_out[input.u64 & BPmask.u64] += p.second;
        }

        //S boxes
        probs_fw_in.swap(probs_fw_out);
        probs_fw_out.clear();

        for (auto p : probs_fw_in) {
            state_t input = p.first;
            SBTopt::sbox(input);
            probs_fw_out[input.u64 & BPmask.u64] += p.second;
        }

    }

    double prob = 0;

    for (auto fw : probs_fw_out) {
            for (auto bw : probs_bw_out) {
                if (fw.first == bw.first) {
                    prob += fw.second * bw.second;
                }
            }
        }

    return (prob > 0);
}


bool valid_mitm(const state_t key, state_t BPmask) {
    state_t original_BPmask = BPmask;
    std::vector<state_t> IList; // list of all possible inputs (per operation)
    std::vector<state_t> OList; // list of all possible outputs (per operation)
    std::unordered_set<state_t, state_hash> OHash;

    // create backwards list first
    state_t initial_output_state = original_output;
    OList.push_back(initial_output_state);

    for (int round = 7; round > 3; --round) {
        state_t control = SBTopt::control_Nr_Gr(round, key, original_input);

        // inverse S boxes
        IList.swap(OList);
        OList.clear();

        for (state_t input : IList) {
            SBTopt::sbox_inv(input);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output.u64);
        }

        // inverse nibble switch
        IList.swap(OList);
        OList.clear();

        for (state_t input : IList) {
            SBTopt::nibbleswitch_inv(input, control);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output.u64);
        }

        SBTopt::bytepermutation_inv(BPmask);

        // inverse byte permutation
        IList.swap(OList);
        OList.clear();

        for (state_t input : IList) {
            SBTopt::bytepermutation_inv(input);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output.u64);
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

        //grid permutation
        for (int n = 15; n >= 0; --n)
        {
            int pos = n ^ 1;
            if (BPmask.getnibble(pos) == 0) continue;

            IList.swap(OList);
            OList.clear();

            for (const state_t& input : IList) {
                state_t val = input;

                bool extcrumbused = SBTopt::partial_grid_permutation_inv(val, n, BPmask, 0, control);
                state_t output = val.u64 & BPmask.u64;
                OList.push_back(output);

                if (extcrumbused == 0) {
                    continue;
                }

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

        std::unordered_set<state_t, state_hash> backwards_list(std::make_move_iterator(OList.begin()), std::make_move_iterator(OList.end()));

        // create forwards list
        IList.clear();
        OList.clear();

        state_t initial_state = original_input;
        SBTopt::bitpermutation(initial_state);
        OList.push_back(initial_state);

        BPmask = original_BPmask;

        for (int round = 0; round < 4; ++round) {
            state_t control = SBTopt::control_Nr_Gr(round, key, original_input);

            // grid permutation
            for (int n = 0; n < 16; ++n)
            {
                int pos = n ^ 1;
                if (BPmask.getnibble(pos) == 0) continue;

                IList.swap(OList);
                OList.clear();

                for (const state_t& input : IList) {
                    state_t val = input;

                    bool extcrumbused = SBTopt::partial_grid_permutation_inv(val, n, BPmask, 0, control);
                    state_t output = val.u64 & BPmask.u64;
                    OList.push_back(output);

                    if (extcrumbused == 0) {
                        continue;
                    }

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
            for (state_t input : IList) {
                SBTopt::bytepermutation(input);
                state_t output = input.u64 & BPmask.u64;
                OList.push_back(output.u64);
            }

            //Nibble switch
            IList.swap(OList);
            OList.clear();

            for (state_t input : IList) {
                SBTopt::nibbleswitch(input, control);
                state_t output = input.u64 & BPmask.u64;
                OList.push_back(output);
            }

            //S boxes
            IList.swap(OList);
            OList.clear();

            for (state_t input : IList) {
                SBTopt::sbox(input);
                state_t output = input.u64 & BPmask.u64;
                OList.push_back(output);

            }
        }

        for (state_t output : OList) {
            if (backwards_list.count(output) > 0) {
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

    std::map<int, double> weights;
    
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

List combine_lists(const List& list_a, const List& list_b, std::map<state_t, double> probs){

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
}

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

int main(int argc, char** argv) {
    //-i 7913287333904857843 -k 16779657253290007  -l 268435455
    std::random_device rd;
    //std::seed_seq seed{ rd(), rd(), rd(), rd() };
    std::seed_seq seed{ 1, 2, 3, 4 };
    std::mt19937_64 rng(seed);

    unsigned kb_strategy;
    unsigned threads = 0;

	po::options_description opts("Command line options");
	opts.add_options()
		("help,h", "Show options") // short option & long option
		("input,i", po::value<std::uint64_t>(&original_input.u64), "Provide input block")
		("key,k", po::value<std::uint64_t>(&original_key.u64), "Provide key (to compute output block)")
		("knownkeybitmask,l", po::value<std::uint64_t>(&key_known_bits_mask.u64)->default_value(0), "Leak key bits to attack")
		("output,o", po::value<std::uint64_t>(&original_output.u64), "Provide output block")
        ("rndin", "Generate input block at random")
        ("rndout", "Generate output block at random")
        ("rndkey", "Generate key at random, and compute output")
        //("strategy", po::value<unsigned>(&kb_strategy)->default_value(0), "Strategy to derive key bit order: 0")
        //("threads,t", po::value<unsigned>(&threads)->default_value(std::thread::hardware_concurrency()), "Number of threads to use (0 = automatic)")
		;
	po::variables_map vm;
	// parse command line
	po::store(po::parse_command_line(argc, argv, opts, false, false), vm);
	// set default values if option was not given, and store arguments in variables
	po::notify(vm);

	if (vm.count("help") || vm.count("key") + vm.count("rndkey") + vm.count("output") + vm.count("rndout") != 1)
	{
		po::print_options_description({opts}); // add other opts as desired in list
		return 0;
	}

    if (vm.count("rndout"))
        original_output = rng();
    
    if (vm.count("key") || vm.count("rndkey") || vm.count("rndout") + vm.count("output") == 0)
    {
        original_output = SBTopt::SBT_cipher(original_key, original_input);
        std::cout << "Out: " << original_output << " " << original_output.u64 << " (computed from Key & In)" << std::endl;
    }
    else if (vm.count("rndout"))
        std::cout << "Out: " << original_output << " " << original_output.u64 << " (randomly sampled)" << std::endl;
    else
        std::cout << "Out: " << original_output << " " << original_output.u64 << " (user parameter)" << std::endl;

    if (vm.count("rndkey"))
    {
        original_key = rng();
        original_key.setbyte(7, 0);
        std::cout << "Key: " << original_key << " " << original_key.u64 << " (randomly sampled)" << std::endl;
    }
    else if (vm.count("key"))
        std::cout << "Key: " << original_key << " " << original_key.u64 << " (user parameter)" << std::endl;
    else if (vm.count("rndout") + vm.count("output") == 0)
        std::cout << "Key: " << original_key << " " << original_key.u64 << " (none/default challenge)" << std::endl;

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
    std::cout << "L8 size: " << L8.keylist.size() << std::endl;/*

    List L67 = combine_lists(L6, L7, probs);
    std::cout << "L67 size: " << L67.keylist.size() << std::endl;

    List L167 = combine_lists(L67, L1, probs);
    std::cout << "L167 size: " << L167.keylist.size() << std::endl;

    List L1567 = combine_lists(L167, L5, probs);
    std::cout << "L1567 size: " << L1567.keylist.size() << std::endl;

    List L15678 = combine_lists(L1567, L8, probs);
    std::cout << "L15678 size: " << L15678.keylist.size() << std::endl;

    List L125678 = combine_lists(L15678, L2, probs);
    std::cout << "L125678 size: " << L125678.keylist.size() << std::endl;

    List L1235678 = combine_lists(L125678, L3, probs);
    std::cout << "L1235678 size: " << L1235678.keylist.size() << std::endl;

    List L12345678 = combine_lists(L1235678, L4, probs);
    std::cout << "L12345678 size: " << L12345678.keylist.size() << std::endl;

    std::cout << "Computed key: ";
    printvec(L12345678.keylist);
    std::cout << "Original key: " << original_key << std::endl;*/
    myfile.close();
    return 0;
};